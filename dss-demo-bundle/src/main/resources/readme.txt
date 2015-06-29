The DSS-Web applications is built as demonstration for a Windows environment and all required elements (like the JRE 1.6) are provided.

To start any application go to the folder:
- ./bin

# For the web-application:
- Webapp-Startup.bat starts the Tomcat server
- Webapp-Shutdown.bat stops the Tomcat server

The HTML page is available via
  http://localhost:8080/
Please make sure that your browser has the corresponding Java-plugin installed and activated.

Required callback-service for the applet is configured on the following address:
  http://localhost:8080/wservice

The web-services (for e.g. integration in another application) are accessible via the following address
  http://localhost:8080/wservice/
There are two SOAP services available, that are described (WSDL) when accessing one of the aforementioned URLs:
1. SignatureService
   http://localhost:8080/wservice/signatureService exposes three operations:
	- signDocument
	- extendSignature
	- getDataToSign
   WSDL information is given via:
   - http://localhost:8080wservice/signatureService?wsdl
   - and (with more details) http://localhost:8080/wservice/signatureService?wsdl=SignatureService.wsdl
2. ValidationService
   http://localhost:8080/wservice/validationService exposes one operation:
   - validateDocument
   WSDL information is given via:
   - http://localhost:8080/wservice/validationService?wsdl
   - and (with more details) http://localhost:8080/wservice/validationService?wsdl=ValidationService.wsdl

Note that the web-application connects to external internet addresses to fetch data (e.g. CRL/OCSP).
If you have a proxy, then you may use the proxy configuration page:
- http://localhost:8080/admin/proxy
When the application is started, the european LoTL and its contained TSLs are fetched immediately.
It is quite "normal" that a TSL URL may not be accessible; this error is logged on the console.
