//! The feature map: a thin strip beside the panes
//! (or above them) standing for the whole image in address order,
//! coloured by what the bytes are, and marked with the cursor, the
//! others' places in a session, the bookmarks and the current search's
//! hits.
//!
//! [`Scale`] lays the image's mapped ranges end to end, the gaps between
//! segments compressed away, and maps an
//! address to a pixel along a strip and a pixel back to an address. The
//! colours are the hex view's overview ([`crate::hex::HexImage::overview`])
//! in address mode, each part's kind as its [`Feature`]; [`runs`] joins
//! equal neighbours so a strip draws one rectangle a run ([`band`]), the
//! hex view's overview strip as well. [`libraries`] tells the code of the
//! library functions signatures named from the program's own.

use std::ops::Range;

use crate::hex::Kind;

/// What the feature map colours a part of the image as.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Feature {
    /// Code of a function.
    Function,
    /// Code of a library function (one a signature names).
    Library,
    /// Code no function holds.
    Code,
    /// Data: typed values, pointers, tables, headers, padding, `.bss`.
    Data,
    /// A string.
    String,
    /// An import's slot.
    Import,
    /// Bytes no analysis typed.
    Unexplored,
}

impl Feature {
    /// Every feature, in the legend's order.
    pub const ALL: [Self; 7] = [
        Self::Function,
        Self::Library,
        Self::Code,
        Self::Data,
        Self::String,
        Self::Import,
        Self::Unexplored,
    ];

    /// The feature of bytes of the hex view's `kind`; `None` for no
    /// bytes (a gap). A function's code is [`Feature::Function`]; which
    /// is a library's, [`libraries`] says.
    pub fn of(kind: Kind) -> Option<Self> {
        match kind {
            Kind::Code => Some(Self::Function),
            Kind::LooseCode => Some(Self::Code),
            Kind::String => Some(Self::String),
            Kind::Import => Some(Self::Import),
            Kind::Header
            | Kind::Table
            | Kind::Pointer
            | Kind::Value
            | Kind::Relocation
            | Kind::Padding
            | Kind::Section
            | Kind::Uninitialised => Some(Self::Data),
            Kind::Unexplored | Kind::Other => Some(Self::Unexplored),
            Kind::Gap => None,
        }
    }

    /// Its name.
    pub fn title(self) -> &'static str {
        match self {
            Self::Function => "Function",
            Self::Library => "Library function",
            Self::Code => "Code outside functions",
            Self::Data => "Data",
            Self::String => "String",
            Self::Import => "Import",
            Self::Unexplored => "Unexplored",
        }
    }
}

/// The image's mapped address ranges laid end to end, gaps compressed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Scale {
    /// The ranges in address order, each with how many mapped bytes come
    /// before it.
    ranges: Vec<(Range<u64>, u64)>,
    /// How many mapped bytes there are.
    total: u64,
}

impl Scale {
    /// The scale of `ranges` (in any order; overlapping and touching ones
    /// joined, empty ones dropped).
    pub fn new(ranges: impl IntoIterator<Item = Range<u64>>) -> Self {
        let mut sorted: Vec<Range<u64>> = ranges.into_iter().filter(|r| r.start < r.end).collect();
        sorted.sort_by_key(|r| r.start);
        let mut joined: Vec<Range<u64>> = Vec::with_capacity(sorted.len());
        for r in sorted {
            match joined.last_mut() {
                Some(last) if r.start <= last.end => last.end = last.end.max(r.end),
                _ => joined.push(r),
            }
        }
        let mut total = 0u64;
        let ranges = joined
            .into_iter()
            .map(|r| {
                let before = total;
                total = total.saturating_add(r.end - r.start);
                (r, before)
            })
            .collect();
        Self { ranges, total }
    }

    /// How many mapped bytes there are.
    pub fn total(&self) -> u64 {
        self.total
    }

    /// Whether nothing is mapped.
    pub fn is_empty(&self) -> bool {
        self.total == 0
    }

    /// The place of `address` among the mapped bytes (0 to the total
    /// less one), if it is mapped.
    pub fn offset(&self, address: u64) -> Option<u64> {
        let i = self
            .ranges
            .partition_point(|(r, _)| r.start <= address)
            .checked_sub(1)?;
        let (r, before) = self.ranges.get(i)?;
        r.contains(&address).then(|| before + (address - r.start))
    }

    /// The address of mapped byte `offset` (past the last: the last).
    pub fn address(&self, offset: u64) -> Option<u64> {
        let offset = offset.min(self.total.checked_sub(1)?);
        let i = self
            .ranges
            .partition_point(|(_, before)| *before <= offset)
            .checked_sub(1)?;
        let (r, before) = self.ranges.get(i)?;
        Some(r.start + (offset - before))
    }

    /// The first pixel of a strip `length` pixels long that mapped byte
    /// `offset` is drawn on (each pixel stands for an equal share of the
    /// bytes; a byte of a small image spans several).
    fn pixel_of_offset(&self, offset: u64, pixels: u64) -> u64 {
        let at = u128::from(offset) * u128::from(pixels) / u128::from(self.total.max(1));
        u64::try_from(at).unwrap_or(u64::MAX).min(pixels - 1)
    }

    /// The pixel along a strip `length` long (whole pixels; 0 to the
    /// last) where `address` is drawn: the first of its byte's, if the
    /// address is mapped.
    pub fn pixel(&self, address: u64, length: f32) -> Option<u64> {
        let pixels = whole(length)?;
        let offset = self.offset(address)?;
        Some(self.pixel_of_offset(offset, pixels))
    }

    /// The address drawn at `pixel` along a strip `length` long: the first
    /// byte drawn from there, else (a pixel inside a byte of a small
    /// image) the byte covering it. A pixel before the strip is its first;
    /// past it, its last.
    pub fn address_at(&self, pixel: f32, length: f32) -> Option<u64> {
        let pixels = whole(length)?;
        if self.total == 0 {
            return None;
        }
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "clamped to the strip's pixels"
        )]
        let p = if pixel.is_nan() || pixel < 0.0 {
            0
        } else {
            (pixel.floor() as u64).min(pixels - 1)
        };
        let total = u128::from(self.total);
        let first = (u128::from(p) * total).div_ceil(u128::from(pixels));
        let mut offset = u64::try_from(first).unwrap_or(u64::MAX);
        if offset >= self.total || self.pixel_of_offset(offset, pixels) > p {
            offset = offset.saturating_sub(1);
        }
        self.address(offset)
    }
}

/// `length` as a whole number of pixels, if at least one.
fn whole(length: f32) -> Option<u64> {
    if length.is_nan() || length < 1.0 {
        return None;
    }
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "a strip's length in pixels"
    )]
    let pixels = length.floor() as u64;
    Some(pixels)
}

/// The runs of equal values among `items` (one per part, `None` for a
/// part left blank): each the parts it covers and its value, in order.
pub fn runs<T: Copy + PartialEq>(
    items: impl IntoIterator<Item = Option<T>>,
) -> Vec<(Range<usize>, T)> {
    let mut out: Vec<(Range<usize>, T)> = Vec::new();
    for (b, item) in items.into_iter().enumerate() {
        let Some(item) = item else {
            continue;
        };
        match out.last_mut() {
            Some((run, v)) if *v == item && run.end == b => run.end = b + 1,
            _ => out.push((b..b + 1, item)),
        }
    }
    out
}

/// Where run `run` of `parts` equal parts is along a strip `length`
/// long: its start and extent (at least a pixel).
#[expect(clippy::cast_precision_loss, reason = "a strip's pixels")]
pub fn band(run: &Range<usize>, parts: usize, length: f32) -> (f32, f32) {
    let part = length / parts.max(1) as f32;
    (
        run.start as f32 * part,
        ((run.end - run.start) as f32 * part).max(1.0),
    )
}

/// The features of an overview's parts (the hex view's, in address mode).
pub fn column(overview: &[(Kind, f32)]) -> Vec<Option<Feature>> {
    overview
        .iter()
        .map(|&(kind, _)| Feature::of(kind))
        .collect()
}

/// `column` with each part of functions' code that is mostly library
/// functions' a [`Feature::Library`] part: of the addresses `sampled` in
/// a part (the rows its overview read), those
/// `library` says are in a library function (`Some(true)`) outnumber
/// those in another (`Some(false)`); outside any function, `None`.
pub fn libraries(
    column: &mut [Option<Feature>],
    sampled: impl Fn(usize) -> Vec<u64>,
    library: impl Fn(u64) -> Option<bool>,
) {
    for (part, feature) in column.iter_mut().enumerate() {
        if *feature != Some(Feature::Function) {
            continue;
        }
        let (mut ours, mut theirs) = (0usize, 0usize);
        for address in sampled(part) {
            match library(address) {
                Some(true) => ours += 1,
                Some(false) => theirs += 1,
                None => {}
            }
        }
        if ours > theirs {
            *feature = Some(Feature::Library);
        }
    }
}

/// Where a strip's band and the lane of its markers' arrows lie across
/// it, in pixels from its edge (the cursor's arrow beside the band): the
/// lane on the panes' side, under the band along
/// the top, left of it down the right.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Across {
    /// Where the band starts.
    pub band: f32,
    /// The band's thickness.
    pub thickness: f32,
    /// Where the lane starts.
    pub lane: f32,
    /// The lane's thickness.
    pub depth: f32,
    /// Whether the strip runs down (at the right of the panes).
    pub vertical: bool,
}

impl Across {
    /// A strip `total` thick, its lane `depth` of it.
    pub fn new(total: f32, depth: f32, vertical: bool) -> Self {
        let total = total.max(0.0);
        let depth = depth.clamp(0.0, total);
        let thickness = total - depth;
        let (band, lane) = if vertical {
            (depth, 0.0)
        } else {
            (0.0, thickness)
        };
        Self {
            band,
            thickness,
            lane,
            depth,
            vertical,
        }
    }

    /// The rows of an arrow in the lane pointing at the band at `centre`
    /// along the strip (rounded to a pixel), from its tip at the band's
    /// edge, 2 pixels long, to its base, each row 2 longer and a pixel
    /// further, the lane's last pixel left clear: each as (start along
    /// the strip, length, place across it).
    pub fn arrow(&self, centre: f32) -> Vec<(f32, f32, f32)> {
        let centre = centre.round();
        let mut rows = Vec::new();
        let mut k = 0.0;
        while k + 1.0 < self.depth.floor() {
            let across = if self.vertical {
                self.band - 1.0 - k
            } else {
                self.lane + k
            };
            rows.push((centre - k - 1.0, 2.0 * (k + 1.0), across));
            k += 1.0;
        }
        rows
    }

    /// How long the arrow's base is along the strip.
    pub fn arrow_base(&self) -> f32 {
        2.0 * (self.depth.floor() - 1.0).max(0.0)
    }
}

#[cfg(test)]
mod tests {
    use super::{Across, Feature, Scale, band, column, libraries, runs};
    use crate::hex::Kind;

    /// Two segments, 0x1000..0x1100 and 0x5000..0x5300, a gap between.
    fn two() -> Scale {
        Scale::new([0x5000..0x5300, 0x1000..0x1100])
    }

    #[test]
    fn segments_are_laid_end_to_end_with_the_gap_compressed() {
        let scale = two();
        assert_eq!(scale.total(), 0x400);
        assert_eq!(scale.offset(0x1000), Some(0));
        assert_eq!(scale.offset(0x10ff), Some(0xff));
        // The gap is not on the strip; the second segment follows the
        // first's last byte at once.
        assert_eq!(scale.offset(0x1100), None);
        assert_eq!(scale.offset(0x4fff), None);
        assert_eq!(scale.offset(0x5000), Some(0x100));
        assert_eq!(scale.offset(0x5300), None);
        assert_eq!(scale.address(0x100), Some(0x5000));
        assert_eq!(scale.address(u64::MAX), Some(0x52ff));
        // On a 4-pixel strip each pixel is 0x100 bytes: the first segment
        // is the first pixel, the second the other three.
        assert_eq!(scale.pixel(0x10ff, 4.0), Some(0));
        assert_eq!(scale.pixel(0x5000, 4.0), Some(1));
        assert_eq!(scale.pixel(0x52ff, 4.0), Some(3));
        assert_eq!(scale.address_at(1.0, 4.0), Some(0x5000));
        assert_eq!(scale.address_at(1.9, 4.0), Some(0x5000));
        // Overlapping and touching ranges join; empty ones are dropped.
        let joined = Scale::new([0x10..0x20, 0x18..0x30, 0x30..0x40, 0x50..0x50]);
        assert_eq!(joined, Scale::new(std::iter::once(0x10..0x40)));
        assert_eq!(joined.total(), 0x30);
    }

    #[test]
    fn every_pixel_goes_to_an_address_drawn_on_it() {
        for (scale, pixels) in [
            (two(), 300u16),
            (two(), 1024),
            (two(), 1025),
            (two(), 4000),
            (
                Scale::new([0x40_0000..0x4a_37c1, 0x6a_0000..0x6b_1234]),
                917,
            ),
        ] {
            let length = f32::from(pixels);
            let mut previous = None;
            for p in 0..pixels {
                let a = scale.address_at(f32::from(p) + 0.5, length).unwrap();
                let at = scale.pixel(a, length).unwrap();
                let p = u64::from(p);
                // Drawn on this pixel (its first), or covering it.
                assert!(at <= p, "pixel {p}: {a:#x} drawn at {at}");
                if scale.total() >= u64::from(pixels) {
                    assert_eq!(at, p, "pixel {p}");
                }
                // The next byte starts past this pixel, or this one does.
                if let Some(next) = scale.offset(a).and_then(|o| scale.address(o + 1))
                    && next != a
                {
                    assert!(scale.pixel(next, length).unwrap() > p || at == p);
                }
                // In address order down the strip.
                assert!(previous.is_none_or(|q| q <= a), "pixel {p}");
                previous = Some(a);
            }
        }
    }

    #[test]
    fn a_tiny_image_spans_several_pixels_a_byte() {
        // Three bytes on a 10-pixel strip: pixels 0–3, 3–6, 6–9.
        let scale = Scale::new(std::iter::once(0x40..0x43));
        assert_eq!(scale.pixel(0x40, 10.0), Some(0));
        assert_eq!(scale.pixel(0x41, 10.0), Some(3));
        assert_eq!(scale.pixel(0x42, 10.0), Some(6));
        let at: Vec<u64> = (0..10)
            .map(|p| {
                scale
                    .address_at(f32::from(u8::try_from(p).unwrap()), 10.0)
                    .unwrap()
            })
            .collect();
        assert_eq!(
            at,
            [0x40, 0x40, 0x40, 0x41, 0x41, 0x41, 0x42, 0x42, 0x42, 0x42]
        );
        // One byte: every pixel is it.
        let one = Scale::new(std::iter::once(7..8));
        assert_eq!(one.pixel(7, 100.0), Some(0));
        assert_eq!(one.address_at(99.0, 100.0), Some(7));
        // Nothing mapped, or a strip under a pixel: nothing.
        assert_eq!(Scale::default().address_at(0.0, 100.0), None);
        assert_eq!(Scale::default().pixel(0, 100.0), None);
        assert_eq!(two().pixel(0x1000, 0.5), None);
        assert_eq!(two().address_at(0.0, 0.0), None);
    }

    #[test]
    fn a_huge_image_keeps_its_precision() {
        // A kernel's halves: 2^47 bytes low, 2^40 high, near the top of
        // the address space.
        let high = 0xffff_fe00_0000_0000u64;
        let scale = Scale::new([0..1 << 47, high..high + (1 << 40)]);
        assert_eq!(scale.total(), (1 << 47) + (1 << 40));
        let length = 1000.0;
        // The high part is the last 1/129 of the strip: 7.75 pixels.
        assert_eq!(scale.pixel(high, length), Some(992));
        assert_eq!(scale.pixel(high + (1 << 40) - 1, length), Some(999));
        // The last pixel's first byte: on it, the byte before on the one
        // before, both in the high half.
        let last = scale.address_at(999.0, length).unwrap();
        assert!(last > high);
        assert_eq!(scale.pixel(last, length), Some(999));
        assert_eq!(scale.pixel(last - 1, length), Some(998));
        // Pixel 992 starts in the low half's last bytes, 993 in the high.
        let a = scale.address_at(992.0, length).unwrap();
        assert!(a < 1 << 47 && a > (1 << 47) - (1 << 40));
        assert!(scale.address_at(993.0, length).unwrap() > high);
        // The very last address is on the last pixel, the first on the
        // first.
        assert_eq!(scale.address(u64::MAX), Some(high + (1 << 40) - 1));
        assert_eq!(scale.pixel(0, length), Some(0));
    }

    #[test]
    fn the_ends_round_inward() {
        let scale = two();
        // Before the strip: its first byte; past its end: the last pixel's
        // first byte; the last byte is on the last pixel.
        assert_eq!(scale.address_at(-5.0, 400.0), Some(0x1000));
        assert_eq!(scale.address_at(f32::NAN, 400.0), Some(0x1000));
        assert_eq!(
            scale.address_at(400.0, 400.0),
            scale.address_at(399.0, 400.0)
        );
        assert_eq!(scale.address_at(1e9, 400.0), Some(0x5000 + 0x2fe));
        assert_eq!(scale.pixel(0x52ff, 400.0), Some(399));
        // A fractional length is its whole pixels.
        assert_eq!(scale.pixel(0x52ff, 400.9), Some(399));
        assert_eq!(scale.address_at(0.0, 400.0), Some(0x1000));
    }

    #[test]
    fn each_kind_has_its_feature() {
        for kind in Kind::ALL {
            let feature = Feature::of(kind);
            let expected = match kind {
                Kind::Code => Some(Feature::Function),
                Kind::LooseCode => Some(Feature::Code),
                Kind::String => Some(Feature::String),
                Kind::Import => Some(Feature::Import),
                Kind::Unexplored | Kind::Other => Some(Feature::Unexplored),
                Kind::Gap => None,
                Kind::Header
                | Kind::Table
                | Kind::Pointer
                | Kind::Value
                | Kind::Relocation
                | Kind::Padding
                | Kind::Section
                | Kind::Uninitialised => Some(Feature::Data),
            };
            assert_eq!(feature, expected, "{kind:?}");
        }
        // Every feature but the library's (a function's, told apart by
        // `libraries`) is some kind's, and each has a name of its own.
        for feature in Feature::ALL {
            assert_eq!(
                Kind::ALL.iter().any(|&k| Feature::of(k) == Some(feature)),
                feature != Feature::Library,
                "{feature:?}"
            );
        }
        let mut titles: Vec<&str> = Feature::ALL.iter().map(|f| f.title()).collect();
        titles.sort_unstable();
        titles.dedup();
        assert_eq!(titles.len(), Feature::ALL.len());
    }

    #[test]
    fn an_overview_colours_in_runs_and_gaps_stay_blank() {
        // One value's run is one band; a blank or another value cuts it.
        let (a, b) = (Some(1), Some(2));
        assert_eq!(
            runs([a, a, a, b, None, b, a, a]),
            [(0..3, 1), (3..4, 2), (5..6, 2), (6..8, 1)]
        );
        assert_eq!(runs::<u32>([None, None]), []);
        let overview = [
            (Kind::Code, 0.5),
            (Kind::Code, 0.6),
            (Kind::Gap, 0.0),
            (Kind::Value, 0.1),
            (Kind::Pointer, 0.2),
            (Kind::String, 0.4),
            (Kind::LooseCode, 0.6),
        ];
        let column = column(&overview);
        assert_eq!(
            runs(column),
            vec![
                (0..2, Feature::Function),
                (3..5, Feature::Data),
                (5..6, Feature::String),
                (6..7, Feature::Code),
            ]
        );
        // A run's band: its share of the strip, at least a pixel.
        assert_eq!(band(&(3..5), 7, 700.0), (300.0, 200.0));
        let (start, extent) = band(&(3..4), 1000, 100.0);
        assert!((start - 0.3).abs() < 1e-5);
        assert!((extent - 1.0).abs() < f32::EPSILON);
        assert_eq!(band(&(0..1), 0, 10.0), (0.0, 10.0));
    }

    /// A part of functions' code is a library's where most of the rows
    /// read there are in library functions; rows outside any function do
    /// not count, and only functions' parts change.
    #[test]
    fn library_parts_are_those_mostly_in_library_functions() {
        // Library functions at 0x100..0x200, the program's at 0x200..0x300,
        // padding (no function) at 0x300..0x400, library functions again
        // from 0x400.
        let library = |address: u64| match address {
            0x100..0x200 | 0x400..0x500 => Some(true),
            0x200..0x300 => Some(false),
            _ => None,
        };
        // Each part's rows, 16 bytes apart.
        let parts = [
            (0x100, 4), // all library
            (0x1e0, 4), // two library, two the program's: a tie
            (0x1d0, 4), // three library, one the program's
            (0x2f0, 4), // one the program's, three padding
            (0x3c0, 4), // padding only (a data part, say)
            (0x3f0, 2), // one padding, one library
        ];
        let sampled = |part: usize| {
            let (start, rows) = parts[part];
            (0..rows).map(|row| start + row * 16).collect()
        };
        let mut features = vec![
            Some(Feature::Function),
            Some(Feature::Function),
            Some(Feature::Function),
            Some(Feature::Function),
            Some(Feature::Data),
            Some(Feature::Function),
        ];
        libraries(&mut features, sampled, library);
        assert_eq!(
            features,
            [
                Some(Feature::Library),
                Some(Feature::Function),
                Some(Feature::Library),
                Some(Feature::Function),
                Some(Feature::Data),
                Some(Feature::Library),
            ]
        );
    }

    /// The lane is on the panes' side of the band (under it at the top,
    /// left of it at the right), and an arrow's tip touches the band,
    /// widening away from it, its base inside the lane.
    #[test]
    fn the_arrows_lane_is_beside_the_band_on_the_panes_side() {
        let top = Across::new(20.0, 6.0, false);
        assert_eq!((top.band, top.thickness, top.lane), (0.0, 14.0, 14.0));
        assert_eq!(
            top.arrow(100.4),
            [
                (99.0, 2.0, 14.0),
                (98.0, 4.0, 15.0),
                (97.0, 6.0, 16.0),
                (96.0, 8.0, 17.0),
                (95.0, 10.0, 18.0),
            ]
        );
        assert!((top.arrow_base() - 10.0).abs() < f32::EPSILON);
        let right = Across::new(20.0, 6.0, true);
        assert_eq!((right.lane, right.band, right.thickness), (0.0, 6.0, 14.0));
        let across: Vec<f32> = right.arrow(50.0).iter().map(|r| r.2).collect();
        assert_eq!(across, [5.0, 4.0, 3.0, 2.0, 1.0]);
        // A strip thinner than its lane is all lane: no band, no arrow
        // past its edge.
        let thin = Across::new(4.0, 6.0, false);
        assert_eq!((thin.thickness, thin.depth), (0.0, 4.0));
        assert!(thin.arrow(10.0).iter().all(|r| r.2 < 4.0));
    }
}
