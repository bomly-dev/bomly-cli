## Source details

Bomly reads registry, remote source-control, and local source-control origins
from SwiftPM resolved data. Older resolved files use `repositoryURL`, which is
SwiftPM's source-control field. An unrecognized pin kind stays unknown.
