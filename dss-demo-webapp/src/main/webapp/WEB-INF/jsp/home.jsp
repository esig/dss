<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>

<h2>
    <spring:message code="label.info" />
</h2>
<p>Please see the notes below for the features of the two applications:</p>
<h3>
    <spring:message code="label.signature.applet" />
</h3>
<ul>
    <li>XAdES detached and enveloping signatures can be used to sign any file.</li>
    <li>XAdES enveloped signature can be used to sign an XML file.</li>
    <li>PDF files can be signed with an enveloped PAdES signature.</li>
    <li>CAdES enveloping or detached signatures can be used to sign any arbitrary files.</li>
    <li>ASiC-S signature can be used to sign any type of files.</li>
    <li>The multiple parallel signatures can be created.</li>
    <li>A user can use PKCS#11-compliant SSCD, MS-CAPI, MOCCA and PKCS#12 to sign.</li>
    <li>Any kind of signature: CAdES, PAdES, XAdES or ASiC-S can be validated.</li>
    <li>A validation policy can be applied.</li>
    <li>Two validation reports are available: Simple and Detailed.</li>
    <li>The Diagnostic Data representing each static information used during the validation process is available.</li>
</ul>
<h3>
    <spring:message code="label.tlmanager" />
</h3>
<ul>
    <li>A Trusted List and List of the List can be created from scratch.</li>
    <li>An existing TSL can be loaded, edited, signed and saved.</li>
    <li>A basic validation is performed at the first step of creating a signature.</li>
</ul>
