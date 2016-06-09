<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>

<h2>REST/SOAP WebServices</h2>

<p>DSS offers some <a href="<spring:url value="/services/" />" title="eSignature REST/SOAP WebServices">REST and SOAP WebServices</a> which allows to execute the following operations : </p>
<ul>
    <li>Compute the digest to be signed (getDataToSign) ;</li>
    <li>Incorporate the signature value in the final file (signDocument) ;</li>
    <li>Extend an existing signature;</li>
    <li>Validate a signature.</li>
</ul>

<p>These services hide the signature complexity (CAdES, PAdES, XAdES, ASiC) and made integration easier.</p>
