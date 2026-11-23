//! The context menus (a right click): which commands of the registry
//! ([`crate::commands`]) a menu holds, by where it opens ([`Surface`])
//! and what is under the pointer ([`Target`]). The items are the
//! registry's commands, so a context menu shows the same titles, keys and
//! states as the menu bar and the palette; the right click moves the
//! cursor to the item first, so the commands act on
//! it.

use crate::commands::{self, Command, Entry, Facts};

/// Where a context menu opens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Surface {
    /// A C pane.
    C,
    /// A listing pane, as text.
    Listing,
    /// A listing pane, as the graph.
    Graph,
    /// A list tab's row (strings, cross-references) or the map's: an
    /// address.
    Row,
    /// A folder of the map.
    Folder,
    /// The feature map.
    FeatureMap,
}

/// What is under the pointer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    /// A variable or parameter (C).
    Variable,
    /// A struct's member (C), where it is used or on its definition's
    /// line.
    Member,
    /// A function's name.
    Function,
    /// Another name of an address (a global, a label, an import).
    Name,
    /// A number.
    Number,
    /// Anything else: the line.
    Line,
}

/// The menu for `target` on `surface`, separators between groups. With
/// text `selected` in the pane (the C's characters, the listing's lines),
/// Copy comes first, whatever is under the pointer.
pub fn menu(surface: Surface, target: Target, selected: bool) -> Vec<Entry> {
    use Command as C;
    let graph_toggle: &[Command] = match surface {
        Surface::Listing | Surface::Graph => &[C::ToggleGraph, C::ShowInIr],
        Surface::C => &[C::ShowInIr],
        Surface::Row | Surface::Folder | Surface::FeatureMap => &[],
    };
    let line: &[Command] = match surface {
        Surface::Row | Surface::Folder | Surface::FeatureMap => &[C::CopyAddress],
        Surface::C | Surface::Listing | Surface::Graph => {
            &[C::Comment, C::StartThread, C::CopyAddress]
        }
    };
    // The corrections of recovery, in the listing.
    let corrections: &[Command] = match surface {
        Surface::Listing | Surface::Graph => &[
            C::MakeCode,
            C::Undefine,
            C::Data,
            C::MakeString,
            C::MakeArray,
            C::MakeFunction,
            C::EditFunction,
            C::DeleteFunction,
        ],
        Surface::C | Surface::Row | Surface::Folder | Surface::FeatureMap => &[],
    };
    let mut groups: Vec<&[Command]> = match (surface, target) {
        (Surface::Folder, _) => vec![&[C::OpenAsTab]],
        (Surface::FeatureMap, _) => vec![&[C::ToggleFeatureMap, C::MoveFeatureMap]],
        (Surface::Row, _) => vec![
            &[C::Follow, C::OpenInNewPane],
            &[C::Rename, C::Xrefs],
            &[C::CopyName, C::CopyAddress],
        ],
        (_, Target::Variable) => vec![
            &[C::Rename, C::SetType, C::EditStruct],
            &[C::Why, C::Origin, C::Xrefs],
            &[C::CopyName],
            line,
        ],
        (_, Target::Member) => vec![
            &[C::Rename, C::SetType, C::Data, C::EditStruct],
            &[C::CopyName],
            line,
        ],
        (_, Target::Function) => vec![
            &[C::Follow, C::OpenInNewPane],
            &[C::Rename, C::SetType, C::RejectSignature],
            &[C::Why, C::Xrefs],
            &[C::PathFrom, C::PathTo],
            graph_toggle,
            &[C::RunFromHere],
            &[C::CopyName],
            line,
            corrections,
        ],
        (_, Target::Name) => vec![
            &[C::Follow, C::OpenInNewPane],
            &[C::Rename],
            &[C::Xrefs],
            &[C::CopyName],
            line,
        ],
        (_, Target::Number) => vec![
            &[C::NumberHex, C::NumberDecimal, C::NumberChar, C::NumberEnum],
            line,
            graph_toggle,
        ],
        (Surface::C, Target::Line) => vec![&[C::Origin], line],
        (_, Target::Line) => vec![&[C::Origin, C::Xrefs], line, graph_toggle, corrections],
    };
    let selected = selected && matches!(surface, Surface::C | Surface::Listing | Surface::Graph);
    if selected {
        groups.insert(0, &[C::CopyName]);
    }
    let mut entries = Vec::new();
    for (i, group) in groups.into_iter().enumerate() {
        // Copy is listed once: first, over a selection.
        let group: Vec<Command> = group
            .iter()
            .copied()
            .filter(|&c| !(selected && i > 0 && c == C::CopyName))
            .collect();
        if group.is_empty() {
            continue;
        }
        if !entries.is_empty() {
            entries.push(Entry::Separator);
        }
        entries.extend(group.into_iter().map(Entry::Command));
    }
    entries
}

/// `command`'s title in `surface`'s menu: the feature map's own menu
/// says what it does to the map (Hide, Show at the Top); elsewhere the
/// registry's ([`commands::title`]).
pub fn title(surface: Surface, command: Command, facts: &Facts) -> &'static str {
    match (surface, command) {
        (Surface::FeatureMap, Command::ToggleFeatureMap) => "Hide",
        (Surface::FeatureMap, Command::MoveFeatureMap) if facts.feature_map_top => {
            "Show at the Right"
        }
        (Surface::FeatureMap, Command::MoveFeatureMap) => "Show at the Top",
        _ => commands::title(command, facts),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{Surface, Target, menu, title};
    use crate::commands::{Command, Entry, Facts, lookup};

    const SURFACES: [Surface; 6] = [
        Surface::C,
        Surface::Listing,
        Surface::Graph,
        Surface::Row,
        Surface::Folder,
        Surface::FeatureMap,
    ];
    const TARGETS: [Target; 6] = [
        Target::Variable,
        Target::Member,
        Target::Function,
        Target::Name,
        Target::Number,
        Target::Line,
    ];

    fn commands(surface: Surface, target: Target) -> Vec<Command> {
        selected_commands(surface, target, false)
    }

    fn selected_commands(surface: Surface, target: Target, selected: bool) -> Vec<Command> {
        menu(surface, target, selected)
            .into_iter()
            .filter_map(|e| match e {
                Entry::Command(c) => Some(c),
                Entry::Submenu { .. } | Entry::Separator => None,
            })
            .collect()
    }

    #[test]
    fn every_menu_is_well_formed_from_the_registry() {
        for surface in SURFACES {
            for target in TARGETS {
                for selected in [false, true] {
                    let entries = menu(surface, target, selected);
                    assert!(!entries.is_empty(), "{surface:?} {target:?}");
                    assert_ne!(entries.first(), Some(&Entry::Separator));
                    assert_ne!(entries.last(), Some(&Entry::Separator));
                    assert!(
                        entries
                            .windows(2)
                            .all(|w| w != [Entry::Separator, Entry::Separator])
                    );
                    let all = selected_commands(surface, target, selected);
                    let unique: BTreeSet<Command> = all.iter().copied().collect();
                    assert_eq!(unique.len(), all.len(), "{surface:?} {target:?}");
                    // Every item is a registry command (its title and keys).
                    assert!(all.iter().all(|&c| lookup(c).is_some()));
                }
            }
        }
    }

    #[test]
    fn a_selection_offers_copy_first_wherever_the_pointer_is() {
        for surface in [Surface::C, Surface::Listing] {
            for target in TARGETS {
                let all = selected_commands(surface, target, true);
                assert_eq!(
                    all.first(),
                    Some(&Command::CopyName),
                    "{surface:?} {target:?}"
                );
            }
        }
        // A row's menu is about its row, whatever a pane selects.
        assert_ne!(
            selected_commands(Surface::Row, Target::Line, true).first(),
            Some(&Command::CopyName)
        );
    }

    #[test]
    fn menus_follow_what_is_under_the_pointer() {
        let variable = commands(Surface::C, Target::Variable);
        for c in [
            Command::Rename,
            Command::Why,
            Command::Origin,
            Command::Xrefs,
            Command::CopyName,
            Command::Comment,
            Command::CopyAddress,
        ] {
            assert!(variable.contains(&c), "{c:?}");
        }
        assert!(!variable.contains(&Command::Follow));
        // A member is edited as its struct's: renamed, retyped, resized.
        let member = commands(Surface::C, Target::Member);
        for c in [
            Command::Rename,
            Command::SetType,
            Command::Data,
            Command::EditStruct,
        ] {
            assert!(member.contains(&c), "{c:?}");
        }
        assert!(!member.contains(&Command::Why));
        // The corrections of recovery are the listing's, not the C's.
        let line = commands(Surface::Listing, Target::Line);
        assert!(line.contains(&Command::Undefine) && line.contains(&Command::MakeFunction));
        assert!(!commands(Surface::C, Target::Line).contains(&Command::Undefine));
        let function = commands(Surface::Listing, Target::Function);
        for c in [
            Command::Follow,
            Command::OpenInNewPane,
            Command::Rename,
            Command::Xrefs,
            Command::ToggleGraph,
            Command::RunFromHere,
            Command::Why,
            Command::RejectSignature,
        ] {
            assert!(function.contains(&c), "{c:?}");
        }
        // A function's own name is explained and rejected where it is
        // named, in the C as in the listing; never a variable's.
        let named = commands(Surface::C, Target::Function);
        assert!(named.contains(&Command::Why) && named.contains(&Command::RejectSignature));
        assert!(!variable.contains(&Command::RejectSignature));
        // The graph toggle belongs to the listing and the graph, not the C.
        assert!(!commands(Surface::C, Target::Function).contains(&Command::ToggleGraph));
        assert!(commands(Surface::Graph, Target::Line).contains(&Command::ToggleGraph));
        let number = commands(Surface::C, Target::Number);
        assert_eq!(
            number.get(..4),
            Some(
                [
                    Command::NumberHex,
                    Command::NumberDecimal,
                    Command::NumberChar,
                    Command::NumberEnum
                ]
                .as_slice()
            )
        );
        assert!(!number.contains(&Command::Rename));
    }

    #[test]
    fn the_feature_maps_menu_hides_it_or_moves_it_to_the_other_side() {
        let entries = commands(Surface::FeatureMap, Target::Line);
        let titled = |facts: &Facts| -> Vec<&str> {
            entries
                .iter()
                .map(|&c| title(Surface::FeatureMap, c, facts))
                .collect()
        };
        let right = Facts {
            feature_map: true,
            ..Facts::default()
        };
        assert_eq!(titled(&right), ["Hide", "Show at the Top"]);
        let top = Facts {
            feature_map_top: true,
            ..right
        };
        assert_eq!(titled(&top), ["Hide", "Show at the Right"]);
        // Elsewhere the registry's titles.
        assert_eq!(
            title(Surface::Row, Command::MoveFeatureMap, &top),
            "Feature Map at the Right"
        );
        assert_eq!(
            commands(Surface::Folder, Target::Line),
            [Command::OpenAsTab]
        );
    }
}
