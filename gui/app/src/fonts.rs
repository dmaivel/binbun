//! The bundled fonts (SIL Open Font License 1.1, licences beside them in
//! `assets/fonts`): Iosevka 34.9.1, the code font; Lilex 2.630, the
//! alternative; IBM Plex Sans 1.1.0, the UI font, and
//! its Medium, the avatars' initials.

use std::borrow::Cow;
use std::sync::LazyLock;

use gpui_kit::App;

/// The bundled code fonts' families, in the font pickers' order.
pub const BUNDLED_CODE: &[&str] = &["Iosevka", "Lilex"];

/// The bundled UI font's family.
pub const BUNDLED_UI: &[&str] = &["IBM Plex Sans"];

/// The avatars' initials' family, in its Medium weight (bundled, so the
/// same outlines everywhere, whatever the UI font).
pub const AVATAR_FAMILY: &str = "IBM Plex Sans";

const AVATAR_MEDIUM: &[u8] = include_bytes!("../assets/fonts/IBMPlexSans-Medium.ttf");

const FONTS: &[&[u8]] = &[
    include_bytes!("../assets/fonts/Iosevka-Regular.ttf"),
    include_bytes!("../assets/fonts/Iosevka-Bold.ttf"),
    include_bytes!("../assets/fonts/Lilex-Regular.ttf"),
    include_bytes!("../assets/fonts/Lilex-Bold.ttf"),
    include_bytes!("../assets/fonts/IBMPlexSans-Regular.ttf"),
    AVATAR_MEDIUM,
    include_bytes!("../assets/fonts/IBMPlexSans-Bold.ttf"),
];

/// Adds the bundled fonts to the text system.
pub fn load(cx: &App) {
    let fonts = FONTS.iter().map(|&bytes| Cow::Borrowed(bytes)).collect();
    if let Err(error) = cx.text_system().add_fonts(fonts) {
        eprintln!("cannot load the bundled fonts: {error}");
    }
}

/// The ink of `letter` in the avatars' font across: its left and right
/// edges from the pen, in ems (its outline's bounds; GPUI gives only
/// the advance on Linux). `None` for a letter it lacks or one with no
/// ink.
pub fn avatar_ink(letter: char) -> Option<(f32, f32)> {
    static FACE: LazyLock<Option<ttf_parser::Face<'static>>> =
        LazyLock::new(|| ttf_parser::Face::parse(AVATAR_MEDIUM, 0).ok());
    let face = FACE.as_ref()?;
    let ink = face.glyph_bounding_box(face.glyph_index(letter)?)?;
    let em = f32::from(face.units_per_em());
    Some((f32::from(ink.x_min) / em, f32::from(ink.x_max) / em))
}

#[cfg(test)]
mod tests {
    use super::avatar_ink;

    #[test]
    fn the_avatar_letters_ink_is_their_outlines_extent_across() {
        // Plex Sans Medium: every capital's ink starts right of the pen
        // and is under an em wide.
        for letter in 'A'..='Z' {
            let (left, right) = avatar_ink(letter).expect("a capital");
            assert!(
                left >= 0.0 && right > left && right - left < 1.0,
                "{letter}"
            );
        }
        // Read across, not down: W is wider than A, A than H, H than
        // Plex's I (a stem with bars), whatever their heights.
        let width = |c| avatar_ink(c).map(|(l, r)| r - l).expect("a capital");
        assert!(width('W') > width('A') && width('A') > width('H') && width('H') > width('I'));
        assert_eq!(avatar_ink(' '), None);
    }
}
