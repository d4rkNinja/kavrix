# Recover data and rules without resurrecting temporary authority

Full backup bundles retain encrypted authorization state, but applying it is an
explicit owner-authenticated step after database recovery. Recovery discards all
archived grants because restoring remaining-use counters could resurrect consumed
or revoked authority. Structured vault transfer carries optional policy definitions
as inert candidates, activated individually after review; it never grants access
merely by importing data. The extra step makes recovery and cross-database transfer
reviewable while retaining the zero-knowledge storage model.
