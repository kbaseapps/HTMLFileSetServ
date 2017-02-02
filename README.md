HTMLFileSetServ
===============

Service for serving the contents of a workspace object as HTML files.

Warnings:
---------

The service caches data to the scratch space defined in the deploy.cfg file,
including private data. The scratch space used by the service must not be made
available to any other processes or users.

The service expects the scratch space defined in the deploy.cfg file to be a
separate space *per server instance*. Multiple server instances writing to the
same scratch space will cause errors.

The service serves arbitrary files from the KBase stores, and any
user can save data to the KBase stores. This means that said user can
submit malicious code to KBase and have that code served up under the
KBase namespace.

It may be worthwhile to restrict creation privileges to specified users,
but based on the understanding of the use case this is not workable.
Caja (https://developers.google.com/caja/) might be useful for protecting
any front end widgets.

Currently the scratch space is cleared on service startup but otherwise grows
indefinitely.

API:
----

X/Y/Z is a reference to a workspace object.  
X is the workspace name or id  
Y is the object name or id  
Z is the version number, or '-' to indicate the latest version.

[zipfile identifier] is a portion of the url that specifies which
html zip file to retrieve from the workspace object if the object may contain
multiple zip files (or references to zip files). The identifier is type
specific.

&lt;path to file&gt; is the path to the file of interest *from the root of the
zip file*.

GET [host]/api/v1/X/Y/Z/$/[zipfile identifier]&lt;path to file&gt;  
...will display the file from zip file specified by the zipfile identifier in
object X/Y/Z.

To specify a workspace reference path, just include the path in the url:

GET [host]/api/v1/X/Y/Z/X/Y/Z/.../X/Y/Z/$/[zipfile identifier]&lt;path to file&gt;

### Mime types

The service uses [Files.probeContentPath()](http://docs.oracle.com/javase/8/docs/api/java/nio/file/Files.html#probeContentType-java.nio.file.Path-)
to determine the `Content-Type` header.

Supported types:
----------------

### HTMLFileSetUtils.HTMLFileSet

The zipfile identifier is left empty:

GET [host]/api/v1/X/Y/Z/$/&lt;path to file&gt;

### KBaseReport.Report

The zipfile identifier is the index into the list of files stored in the value
of the "html_links" key in the workspace object.

GET [host]/api/v1/X/Y/Z/$/3/&lt;path to file&gt;
