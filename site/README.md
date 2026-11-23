# binbun.org

The website: the landing page, the download page and the docs, built with [Zola](https://www.getzola.org) from our own templates and deployed to Cloudflare as a Worker with static assets.

- `zola.toml`: the configuration, and under `[extra]` the release's `status` and, until a release is published, the `version` and `released` the download page and the landing page's button offer. After, they offer the latest release's: the build reads `static/latest.json`, which `scripts/site/release-files.sh` fetches from the GitHub releases before it (with `install.sh` and `install/`, not committed), so publishing a release is all it takes.
- `templates/`: `index.html` (landing), `download.html`, `page.html` and `section.html` (the docs, with their sidebar and table of contents), `blog.html` and `blog-page.html` (the blog's list and posts), `404.html`, all extending `base.html`; `atom.xml` is the blog's feed (`/blog/atom.xml`), with each post's description as its summary.
- `static/`: `style.css`, the images, the favicons and `_headers` (Cloudflare's response headers by path).
- Link previews: `base.html` gives every page Open Graph and Twitter tags (its title and description, else the site's; a canonical URL; a blog post is an article) and an image (the `preview_image` block). The landing page, the download page and the blog show `static/assets/og.png` (the icon, the name and the dark hero screenshot); each post its own card, `static/assets/blog/<slug>.png` (its title and date), unless it sets `[extra] image = "assets/…"`; the docs none (`page.html`, `section.html`: text-only cards). `scripts/site/og-image.sh` makes them all: run it after adding a post or changing a post's title or date (its page fails to build without its card), the hero or the icon.
- The landing page's three story sections use real default-dark app crops in `static/assets/story-*.webp`. Keep their alt text and image dimensions in `templates/index.html` in step with new captures. The undefined-value example is `examples/undefined/twin.s`; verification compares interpreted lifted and structured forms, not compiled C running natively. The download icon is copied from `gui/app/assets/logo/binbun-icon.svg`.
- `content/`: `_index.md` (landing), `download.md`, `docs/` and `blog/`. A docs page is Markdown with a title and a weight (`+++ title = "…" weight = N +++`, optionally `description = "…"`); the sidebar lists the pages by weight, then each section's. Link pages as `@/docs/<page>.md`.
- A blog post is Markdown with a title, a date and a one-line description (`+++ title = "…" date = YYYY-MM-DD description = "…" +++`), newest first in the list and the feed, and its link preview card from `scripts/site/og-image.sh` (committed with it). The list shows its opening, what is above `<!-- more -->` (else the description); the feed and link previews its description. `draft = true` keeps it out of the build until it is approved; `zola serve --drafts` shows it. A release's post answers `/releases/X.Y.Z/` with `aliases = ["releases/X.Y.Z/"]` (the address in the update checker's examples), which exists only once the post is published; `latest.json`'s `notes` link to the GitHub release.
- `content/docs/reference/` (except its `_index.md`) and `snippets/` (the landing page's code panel) are generated: never edit them by hand.

## Hero images

The hero's two themes, the app's default dark and light themes One Dark and One Light (`static/assets/preview/*.webp`, also the README's top image), are taken by hand, not by `scripts/preview.sh` (which shoots a single window and would replace them with one): a three-person session in a private headless sway at 1920x1200, each window on an output of its own. Three GUIs open the pinned Debian bash `scripts/preview.sh` fetches (`target/preview/`) at `get_directory_stack`, each with its own HOME and `USER` (ana, kit, sam) and settings with `[symbols] download = "never"` and `[updates] check = "never"` (no debug-information or update bars). ana shares through File > Share (LAN only) with the listing, the C and the Chat panel showing; kit and sam join through File > Join with the ticket (pasted, not typed), and ana admits them as editors from the two approval cards. A join opens the share's project at `main`, so kit and sam go back to `get_directory_stack`. kit clicks `v6` in the C (line 39, the loop's `make_word_list` call) and renames it `words` (N), sam clicks `v11` on line 51 (the working directory's `make_word_list`), then the three post a short exchange about the function, pasted into the chat: ana "a1 & 1 asks for polite_directory_format: ~ for $HOME", kit "renamed v6 to words: it's the WORD_LIST that comes back", sam "make_word_list prepends, so the cwd ends up first", ana "and if get_working_directory fails, it's just \".\"". For each theme ana's settings file is rewritten (`window.theme`; the app reloads it live) and ana's output taken with `grim`, then encoded with `magick … -strip -define webp:lossless=true -define webp:method=6 -quality 100`. `scripts/site/og-image.sh` makes `og.png` from the dark one.

## Generate

```sh
BINBUN=path/to/binbun scripts/site/generate.py
```

From the repository's root, this writes the Python API page (from `python/binbun`'s stubs, its modules' docstrings and the extension's doc comments in `crates/binbun-py/src`), the C API page (from `binbun/disasm.h`'s comments), the command-line page (from the `binbun --help` of the binary given, the app's build) and the landing page's examples (`examples/*/quick_start.*`). `python`, `c`, `cli` or `landing` makes one part only; `--check` writes nothing and fails if a file is not current. The same sources give the same bytes. CI checks every part but the command line's, which needs a binbun build: regenerate it when the commands change.

## Preview

With the Zola version `.github/workflows/site.yml` pins (`ZOLA_VERSION`):

```sh
cd site
zola serve                        # http://127.0.0.1:1111, rebuilt on every change
zola check --skip-external-links  # internal links, as CI does
zola build                        # into public/
```

`/install.sh`, `/install/X.Y.Z.sh` and `/latest.json` come from the GitHub releases at deploy, so a preview has none of them.

## Deploy

`.github/workflows/site.yml` builds the site on every pull request that touches it, and on a push to `main` and after each published release (`release.yml` calls it) it also deploys: it adds the release files (`scripts/site/release-files.sh`: each release's `install.sh` as `/install/X.Y.Z.sh`, the latest full release's as `/install.sh` with its `latest.json`), then runs `wrangler deploy` with `wrangler.jsonc` (the Worker `binbun-org` on the custom domain `binbun.org`). It needs two repository secrets: `CLOUDFLARE_API_TOKEN` (a token allowed to edit the account's Workers scripts and the zone's Workers routes) and `CLOUDFLARE_ACCOUNT_ID`. By hand, from `site/` after a build: `npx wrangler deploy`.
