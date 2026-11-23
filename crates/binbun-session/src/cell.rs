//! What a session owns, without leaks: the file's bytes with the image
//! parsed from them ([`Loaded`]), and that with the database recovered from
//! the image ([`Analysed`]). The image borrows the bytes and the database
//! the image, so each is a self-referential cell ([`self_cell`]: the
//! borrow checked by the compiler, the `unsafe` inside the crate).

use std::sync::Arc;

use binbun::Database;
use binbun_loader::Image;
use self_cell::self_cell;

self_cell!(
    /// The file's bytes and the image parsed from them.
    pub(crate) struct Loaded {
        owner: Vec<u8>,
        #[covariant]
        dependent: Image,
    }
    impl {Debug}
);

self_cell!(
    /// The image and the database recovered from it.
    pub(crate) struct Analysed {
        owner: Arc<Loaded>,
        #[covariant]
        dependent: Database,
    }
    impl {Debug}
);
