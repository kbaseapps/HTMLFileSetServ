# HTMLFileSetServ
---

Service for serving the content of a HTMLFileSet object as HTML files.

**Note:** expects the scratch space defined in the deploy.cfg to be a separate
space *per server instance*. Multiple server instances writing to the same
scratch space will cause errors.