# HTMLFileSetServ
-----------------

Service for serving the content of a HTMLFileSet object as HTML files.

**Note:** expects the scratch space defined in the deploy.cfg to be a separate
space *per server instance*. Multiple server instances writing to the same
scratch space will cause errors.

Currently only supports the HTMLFileSetUtils.HTMLFileSet type.

API:
====

X/Y/Z is a reference to a workspace object of the HTMLFileSet type.  
X is the workspace name or id  
Y is the object name or id  
Z is the version number, or '-' to indicate the latest version.

&lt;path to file&gt; is the path to the file of interest *from the root of the
zip file*.

GET [host]/api/v1/X/Y/Z/$/&lt;path to file&gt;  
...will display the file from the zip file in object X/Y/Z.

To specify a workspace reference path, just include the path in the url:

GET [host]/api/v1/X/Y/Z/X/Y/Z/.../X/Y/Z/$/&lt;path to file&gt;
