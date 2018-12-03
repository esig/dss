## DSS : Digital Signature Service

This is the official repository for project DSS : https://ec.europa.eu/cefdigital/wiki/display/CEFDIGITAL/eSignature. 

# Issue Tracker

Please, use the new JIRA for project is on https://ec.europa.eu/cefdigital/tracker/projects/DSS/issues. 

# Maven repository

The release is published on CEF Digital repository : 

https://ec.europa.eu/cefdigital/artifact/#welcome

<pre>
&lt;repository&gt;
  &lt;id&gt;cefdigital&lt;/id&gt;
  &lt;name&gt;cefdigital&lt;/name&gt;
  &lt;url&gt;https://ec.europa.eu/cefdigital/artifact/content/repositories/esignaturedss/&lt;/url&gt;
&lt;/repository&gt;
</pre>

# Documentation

The [documentation](dss-cookbook/src/main/asciidoc/dss-documentation.adoc) and samples are available in the dss-cookbook module. [SoapUI project](dss-cookbook/src/main/soapui) and [Postman project](dss-cookbook/src/main/postman) are also provided to illustrate SOAP/REST calls.

The JavaDoc is available on https://ec.europa.eu/cefdigital/DSS/webapp-demo/apidocs/index.html

# Demonstration

The release is deployed on https://ec.europa.eu/cefdigital/DSS/webapp-demo 

# Ready-to-use bundles

Bundles which contain the above demonstration can be downloaded from the [Maven repository](https://ec.europa.eu/cefdigital/artifact/content/repositories/esignaturedss/eu/europa/ec/joinup/sd-dss/dss-demo-bundle/).

The code of the demonstration can be found on https://ec.europa.eu/cefdigital/code/projects/ESIG/repos/dss-demos/browse

# Licenses

The DSS project is delivered under dual-license : 

- All modules, except 'sscd-mocca-adapter', are licensed under the terms of the Lesser General Public License (LPGL), version 2.1.

- The module 'sscd-mocca-adapter' is licensed under the terms of the European Union Public License (EUPL), version 1.1.

The terms of each license can be found in the main directory of the DSS source repository:

- [![License (EUPL version 1.1)](https://img.shields.io/badge/license-EUPL%20version%201.1-blue.svg?style=flat-square)](https://opensource.org/licenses/EUPL-1.1)
- [![License (LGPL version 2.1)](https://img.shields.io/badge/license-GNU%20LGPL%20version%202.1-blue.svg?style=flat-square)](https://opensource.org/licenses/LGPL-2.1)

SPDX-License-Identifier : LGPL-2.1 OR EUPL-1.1


[![SonarCloud](https://sonarcloud.io/api/project_badges/measure?project=eu.europa.ec.joinup.sd-dss%3Asd-dss&metric=alert_status)](https://sonarcloud.io/dashboard?id=eu.europa.ec.joinup.sd-dss%3Asd-dss)
