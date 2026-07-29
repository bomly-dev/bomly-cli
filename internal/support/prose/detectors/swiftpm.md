## Source details

Bomly reads registry, remote source-control, and local source-control origins
from SwiftPM resolved data. Older resolved files use `repositoryURL`, which is
SwiftPM's source-control field. Remote source-control packages remain eligible
for vulnerability matching because the repository URL is their Swift package
identity. An unrecognized pin kind stays unknown.
