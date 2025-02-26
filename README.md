## DSS : Digital Signature Service

This is the official repository for project DSS : https://ec.europa.eu/digital-building-blocks/wikis/display/DIGITAL/Digital+Signature+Service+-++DSS. 

# Issue Tracker

Please, use the new JIRA for project is on https://ec.europa.eu/digital-building-blocks/tracker/projects/DSS/issues. 

# Requirements

The latest version of DSS framework has the following minimal requirements:

 * Java 11 and higher (tested up to Java 21) for the build is required. For usage Java 8 is a minimum requirement;
 * Maven 3.6 and higher;
 * Memory and Disk: see minimal requirements for the used JVM. In general the higher available is better;
 * Operating system: no specific requirements (tested on Windows and Linux).

# Maven repository

The release is published on Maven Central repository : 

https://central.sonatype.com/search?q=eu.europa.ec.joinup.sd-dss

<pre>
&lt;!-- Add dss-bom for easy integration --&gt;
&lt;dependencyManagement&gt;
    &lt;dependencies&gt;
        &lt;dependency&gt;
            &lt;groupId&gt;eu.europa.ec.joinup.sd-dss&lt;/groupId&gt;
            &lt;artifactId&gt;dss-bom&lt;/artifactId&gt;
            &lt;version&gt;5.13.1&lt;/version&gt;
            &lt;type&gt;pom&lt;/type&gt;
            &lt;scope&gt;import&lt;/scope&gt;
        &lt;/dependency&gt;
    &lt;/dependencies&gt;
&lt;/dependencyManagement&gt;

&lt;!-- Add required modules (example) --&gt;
&lt;dependencies&gt;
    &lt;dependency&gt;
        &lt;groupId&gt;eu.europa.ec.joinup.sd-dss&lt;/groupId&gt;
        &lt;artifactId&gt;dss-utils-apache-commons&lt;/artifactId&gt;
    &lt;/dependency&gt;
    &lt;dependency&gt;
        &lt;groupId&gt;eu.europa.ec.joinup.sd-dss&lt;/groupId&gt;
        &lt;artifactId&gt;dss-xades&lt;/artifactId&gt;
    &lt;/dependency&gt;
    ...
&lt;/dependencies&gt;
</pre>

# Build and usage

A simple build of the DSS Maven project can be done with the following command:

```
mvn clean install
```

This installation will run all unit tests present in the modules, which can take more than one hour to do the complete build.

In addition to the general build, the framework provides a list of custom profiles, allowing a customized behavior:

 * quick - disables unit tests and java-doc validation, in order to process the build as quick as possible (takes 1-2 minutes). This profile cannot be used for a primary DSS build (see below).
 * quick-init - is similar to the `quick` profile. Disables java-doc validation for all modules and unit tests excluding some modules which have dependencies on their test classes. Can be used for the primary build of DSS.
 * slow-tests - executes all tests, including time-consuming unit tests.
 * owasp - runs validation of the project and using dependencies according to the [National Vulnerability Database (NVD)](https://nvd.nist.gov).
 * jdk19-plus - executed automatically for JDK version 9 and higher. Provides a support of JDK 8 with newer versions.
 * spotless - used to add a licence header into project files.
 
In order to run a build with a specific profile, the following command must be executed:

```
mvn clean install -P *profile_name*
```

# Documentation

The [documentation](dss-cookbook/src/main/asciidoc/dss-documentation.adoc) and samples are available in the dss-cookbook module. [SoapUI project](dss-cookbook/src/main/soapui) and [Postman project](dss-cookbook/src/main/postman) are also provided to illustrate SOAP/REST calls.

In order to build the documentation by yourself, the following command must be executed in *dss-cookbook* module:

```
mvn clean install -P asciidoctor
```

# JavaDoc

The JavaDoc is available on https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/apidocs/index.html

# Demonstration

The release is deployed on https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo

The source code of the demonstrations is available on https://github.com/esig/dss-demonstrations

# Ready-to-use bundles

Bundles which contain the above demonstration can be downloaded from the [Maven repository](https://ec.europa.eu/digital-building-blocks/artifact/service/rest/repository/browse/esignaturedss/eu/europa/ec/joinup/sd-dss/dss-demo-bundle/).

The code of the demonstration can be found on https://ec.europa.eu/digital-building-blocks/code/projects/ESIG/repos/dss-demos/browse

# Licenses

The DSS project is delivered under the terms of the Lesser General Public License (LGPL), version 2.1 

[![License (LGPL version 2.1)](https://img.shields.io/badge/license-GNU%20LGPL%20version%202.1-blue.svg?style=flat-square)](https://opensource.org/licenses/LGPL-2.1)

SPDX-License-Identifier : LGPL-2.1

[![SonarCloud](https://sonarcloud.io/api/project_badges/measure?project=eu.europa.ec.joinup.sd-dss%3Asd-dss&metric=alert_status)](https://sonarcloud.io/dashboard?id=eu.europa.ec.joinup.sd-dss%3Asd-dss)
