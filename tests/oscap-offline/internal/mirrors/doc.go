// Package mirrors compares each standalone OVAL check against the copy of it
// embedded in the combined datastream.
//
// The same definitions live in two places:
//
//	gpos/.../ssg-chainguard-xccdf/OvalDefinitions/<Name>.xml   evaluable on its
//	    own with `oscap oval eval <file>`
//	gpos/.../ssg-chainguard-gpos-ds.xml                        the copy
//	    oscap-docker and the openscap image actually evaluate
//
// The standalone files are the source and the datastream is, in principle,
// built from them: chainguard-dev/oscap-playground assembles it when a new SRG
// version lands, reading each standalone file and embedding it verbatim.
// Between SRG bumps the datastream is edited by hand and the generator does not
// run, so the two drift — and the generated artifact is the one that ships.
//
// Nothing else compares them. Schema validation checks each copy in isolation,
// so a change applied to one and not the other passes: that is how
// openssh-sftp-server came to be banned by the standalone RemoteAccessServices
// check while the shipped datastream ignored it. Keeping this green is also
// what makes a future regeneration safe, since a datastream that already
// matches its sources cannot be silently reverted by rebuilding it.
//
// # What counts as a difference
//
// Findings are split by consequence rather than treated alike.
//
// Functional content — the criteria tree and every test, object, state and
// variable — is an error: the two copies would evaluate the same image
// differently.
//
// Metadata (title, description, reference, affected) is a warning. The copies
// disagree today on a <reference source> reading "Custom" in every standalone
// file and "CIS" in five embedded blocks, which changes no verdict. Since
// generation copies the standalone file verbatim, the standalone spelling is
// canonical by construction and those embedded values are simply stale, but
// correcting them is a content change to the shipped datastream and is not
// bundled with the comparison itself.
//
// # Why entities, not a flat node list
//
// Comparison is per entity, keyed by OVAL id, with each entity canonicalised
// recursively so a child's path from its entity root is part of its identity.
// Flattening both copies into one ordered list of nodes — the obvious approach
// — is wrong three ways:
//
//   - a difference that is a permutation or a count change reports nothing
//     locatable, only that the two sides disagree;
//   - listing two tests in a different order reads as functional drift although
//     it is schema-valid, changes no verdict, and is something the generator is
//     free to do — a false positive on the very axis being gated;
//   - a flat list loses which parent a child belongs to, so a relocated element
//     is caught only as a side effect of ordering rather than by comparing
//     structure.
//
// Keying on id fixes all three: order between entities stops mattering, order
// within them is preserved where the schema constrains it, and a finding can
// name the entity and show both values.
//
// Comparison is semantic — namespace-resolved element name, attributes and text
// — rather than byte-for-byte, because the generator re-serializes what it
// parses, so layout legitimately differs while structure must not. Namespace
// declarations are excluded for the same reason: a document may bind the
// independent-component namespace to a prefix or redeclare it as the default,
// and the two forms mean the same thing.
package mirrors
