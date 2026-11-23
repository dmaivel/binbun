//! Styled text with clickable ranges that the mouse also selects, as the
//! window's text selection (`gpui_kit::base::TextSelection`, which the
//! window's root draws over and copies from): an [`InteractiveText`] taking
//! part in it. A drag selects; a press and release in one range is the
//! range's click.

use std::ops::Range;
use std::panic::Location;

use gpui_kit::base::{TextSelectionHandle, TextSelectionRegistration, TextSelectionRun};
use gpui_kit::{
    App, Bounds, ElementId, GlobalElementId, Hitbox, Hsla, InspectorElementId, InteractiveText,
    LayoutId, Pixels, Point, SharedString, StyledText, TextLayout, Window, prelude::*,
};

/// An [`InteractiveText`] the mouse selects.
pub struct SelectableText {
    id: ElementId,
    text: SharedString,
    layout: TextLayout,
    inner: InteractiveText,
    selection: Hsla,
}

impl SelectableText {
    /// `styled` (laid out from `text`), its interactions as `interact`
    /// adds them, selected in `selection`.
    pub fn new(
        id: impl Into<ElementId>,
        text: SharedString,
        styled: StyledText,
        selection: Hsla,
        interact: impl FnOnce(InteractiveText) -> InteractiveText,
    ) -> Self {
        let id = id.into();
        let layout = styled.layout().clone();
        Self {
            inner: interact(InteractiveText::new(id.clone(), styled)),
            id,
            text,
            layout,
            selection,
        }
    }
}

impl IntoElement for SelectableText {
    type Element = Self;

    fn into_element(self) -> Self::Element {
        self
    }
}

impl Element for SelectableText {
    type RequestLayoutState = TextSelectionHandle;
    type PrepaintState = Hitbox;

    fn id(&self) -> Option<ElementId> {
        Some(self.id.clone())
    }

    fn source_location(&self) -> Option<&'static Location<'static>> {
        None
    }

    fn request_layout(
        &mut self,
        global_id: Option<&GlobalElementId>,
        inspector_id: Option<&InspectorElementId>,
        window: &mut Window,
        cx: &mut App,
    ) -> (LayoutId, Self::RequestLayoutState) {
        let text = self.text.clone();
        let handle = match global_id {
            Some(global_id) => window.with_element_state(global_id, |kept, _| {
                let handle: TextSelectionHandle =
                    kept.unwrap_or_else(|| TextSelectionHandle::new(text, cx));
                (handle.clone(), handle)
            }),
            None => TextSelectionHandle::new(text, cx),
        };
        let (layout, ()) = self
            .inner
            .request_layout(global_id, inspector_id, window, cx);
        (layout, handle)
    }

    fn prepaint(
        &mut self,
        global_id: Option<&GlobalElementId>,
        inspector_id: Option<&InspectorElementId>,
        bounds: Bounds<Pixels>,
        handle: &mut Self::RequestLayoutState,
        window: &mut Window,
        cx: &mut App,
    ) -> Self::PrepaintState {
        let hitbox = self
            .inner
            .prepaint(global_id, inspector_id, bounds, &mut (), window, cx);
        let registration = TextSelectionRegistration::new(hitbox.clone(), bounds)
            .with_text_bounds(vec![bounds])
            .with_rendered_element(handle, window, cx);
        handle.register(registration, window, cx);
        hitbox
    }

    fn paint(
        &mut self,
        global_id: Option<&GlobalElementId>,
        inspector_id: Option<&InspectorElementId>,
        bounds: Bounds<Pixels>,
        handle: &mut Self::RequestLayoutState,
        hitbox: &mut Self::PrepaintState,
        window: &mut Window,
        cx: &mut App,
    ) {
        let run = TextSelectionRun::new(self.text.clone(), self.layout.clone(), bounds);
        let projection = handle.update_runs(&[run], cx);
        for range in projection.ranges().iter().flatten() {
            for quad in selection_quads(&self.layout, range.clone()) {
                window.paint_quad(gpui_kit::fill(quad, self.selection));
            }
        }
        self.inner
            .paint(global_id, inspector_id, bounds, &mut (), hitbox, window, cx);
    }
}

/// The rectangles covering `range` of `layout`: a line's part, or the
/// first line's end, the lines between and the last line's start.
fn selection_quads(layout: &TextLayout, range: Range<usize>) -> Vec<Bounds<Pixels>> {
    let (Some(start), Some(end)) = (
        layout.position_for_index(range.start),
        layout.position_for_index(range.end),
    ) else {
        return Vec::new();
    };
    let bounds = layout.bounds();
    let height = layout.line_height();
    if start.y == end.y {
        return vec![Bounds::from_corners(
            start,
            Point::new(end.x, end.y + height),
        )];
    }
    let mut quads = vec![Bounds::from_corners(
        start,
        Point::new(bounds.right(), start.y + height),
    )];
    if end.y > start.y + height {
        quads.push(Bounds::from_corners(
            Point::new(bounds.left(), start.y + height),
            Point::new(bounds.right(), end.y),
        ));
    }
    quads.push(Bounds::from_corners(
        Point::new(bounds.left(), end.y),
        Point::new(end.x, end.y + height),
    ));
    quads
}
