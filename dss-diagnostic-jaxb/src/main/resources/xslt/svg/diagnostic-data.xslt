<?xml version="1.0"?>

<xsl:stylesheet version="2.0" 
		xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
		xmlns:xs="http://www.w3.org/2001/XMLSchema"
    	xmlns:diag="http://dss.esig.europa.eu/validation/diagnostic"
		xmlns="http://www.w3.org/2000/svg">
		
 <xsl:output
   method="xml"
   indent="yes"
   standalone="no"
   doctype-public="-//W3C//DTD SVG 1.1//EN"
   doctype-system="http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd"
   media-type="image/svg" />
 
	<xsl:template match="/diag:DiagnosticData">
	  <svg xmlns="http://www.w3.org/2000/svg">
		<style>
			.trusted {
				stroke: green;
			}
			.not-trusted {
				stroke: black;
			}
		    
			.revoked {
				stroke: red;
			}
			.not-revoked {
				stroke: green;
			}
		</style> 
	  	<defs>
	  	
			<g id="signature-symbol">
				<circle cx="2" cy="2" r="2" fill="blue" />   
	  		</g>
			<g id="timestamp-symbol">
				<circle cx="2" cy="2" r="2" fill="green" />
	  		</g>
	  		
			<g id="revocation-symbol">
			    <line x1="0" y1="0" x2="6" y2="6" stroke-width="1" />
			    <line x1="0" y1="6" x2="6" y2="0" stroke-width="1" />
	  		</g>
	  		
    		<g id="range">
			    <line x1="0" y1="0" x2="0" y2="4" stroke-width="1" />
			    <line x1="0" y1="2" x2="100%" y2="2" stroke-width="1" />
			    <line x1="100%" y1="0" x2="100%" y2="4" stroke-width="1" />
	  		</g>
	  		
	  		<g id="timeline">
			    <line x1="795" y1="0" x2="800" y2="5" stroke="blue" stroke-width="1" />
			    <line x1="795" y1="10" x2="800" y2="5" stroke="blue" stroke-width="1" />
			    <line x1="0" y1="5" x2="800" y2="5" stroke="blue" stroke-width="1" />
	  		</g>
	  		
	  	</defs>
	  
  		<text id="svg-validation-time" y="270">
  			<title class="date"><xsl:value-of select="diag:ValidationDate" /></title>
  			?
		</text>

		<xsl:apply-templates select="diag:UsedCertificates/diag:Certificate"/>
		<xsl:apply-templates select="diag:UsedRevocations/diag:Revocation"/>
		<xsl:apply-templates select="diag:UsedTimestamps/diag:Timestamp"/>
		<xsl:apply-templates select="diag:Signatures/diag:Signature"/>
		
		<svg id="global-timeline" y="250" height="10">
  			<use href="#timeline" />
  		</svg>
  		
	  </svg>
	</xsl:template>
	
	<xsl:template match="diag:Signature">
		
  		<use href="#signature-symbol" class="svg-signature">
	
			<xsl:attribute name="id"><xsl:value-of select="@Id" /></xsl:attribute>
			
			<title><xsl:value-of select="@Id" /></title>
			
			<text class="svg-claimed-signing-time date" style="display:none">
				<xsl:value-of select="diag:ClaimedSigningTime" />
			</text>
			
			<xsl:if test="diag:SigningCertificate/@Certificate">
				<text class="svg-signing-cert leaf" style="display:none">
					<xsl:value-of select="diag:SigningCertificate/@Certificate" />
				</text>
			</xsl:if>
			
			<xsl:apply-templates select="diag:FoundTimestamps/diag:FoundTimestamp" />
		</use>
	</xsl:template>
	
	<xsl:template match="diag:FoundTimestamp">
		<text class="svg-found-timestamp" style="display:none">
			<xsl:value-of select="@Timestamp" />
		</text>
	</xsl:template>
	
	<xsl:template match="diag:Timestamp">
		<svg class="svg-timestamp"> 
			<xsl:attribute name="id"><xsl:value-of select="@Id" /></xsl:attribute>
			
			<title><xsl:value-of select="@Id" /></title>
			
			<text class="svg-production-time date" style="display:none">
				<xsl:value-of select="diag:ProductionTime" />
			</text>
			
			<xsl:if test="diag:SigningCertificate/@Certificate">
				<text class="svg-signing-cert leaf" style="display:none">
					<xsl:value-of select="diag:SigningCertificate/@Certificate" />
				</text>
			</xsl:if>
			
  			<use href="#timestamp-symbol"  />
		</svg>
	</xsl:template>
	
	<xsl:template match="diag:Certificate">
		<svg class="svg-certificate" height="4">
			<xsl:attribute name="id"><xsl:value-of select="@Id" /></xsl:attribute>			

			<title><xsl:value-of select="@Id" /></title>
			
			<text class="svg-not-before date" style="display:none">
				<xsl:value-of select="diag:NotBefore" />
			</text>
			<text class="svg-not-after date" style="display:none">
				<xsl:value-of select="diag:NotAfter" />
			</text>
			
			<xsl:if test="diag:SigningCertificate/@Certificate">
				<text class="svg-signing-cert" style="display:none">
					<xsl:value-of select="diag:SigningCertificate/@Certificate" />
				</text>
			</xsl:if>
			
  			<use href="#range">
  				<xsl:choose>
	  				<xsl:when test="contains(diag:Trusted,'true')">
	  					<xsl:attribute name="class">trusted</xsl:attribute>
	  				</xsl:when>
	  				<xsl:otherwise>
	  					<xsl:attribute name="class">not-trusted</xsl:attribute>
	  				</xsl:otherwise>
  				</xsl:choose>
  			</use>
		</svg>
		
		<xsl:apply-templates select="diag:Revocations/diag:CertificateRevocation"/>
	</xsl:template>
	
	<xsl:template match="diag:Revocation">
		<rect width="200" height="10" fill="red" class="svg-revocation">
			<xsl:attribute name="id"><xsl:value-of select="@Id" /></xsl:attribute>			

			<text class="svg-production-date date">
				<xsl:value-of select="diag:ProductionDate" />
			</text>
			<text class="svg-this-update date">
				<xsl:value-of select="diag:ThisUpdate" />
			</text>
			<xsl:if test="diag:NextUpdate">
				<text class="svg-next-update date">
					<xsl:value-of select="diag:NextUpdate" />
				</text>
			</xsl:if>
			<xsl:if test="diag:ExpiredCertsOnCRL">
				<text class="svg-expired-certs-on-crl date">
					<xsl:value-of select="diag:ExpiredCertsOnCRL" />
				</text>
			</xsl:if>
			<xsl:if test="diag:ArchiveCutOff">
				<text class="svg-archive-cut-off date">
					<xsl:value-of select="diag:ArchiveCutOff" />
				</text>
			</xsl:if>
			
			<xsl:if test="diag:SigningCertificate/@Certificate">
				<text class="svg-signing-cert">
					<xsl:value-of select="diag:SigningCertificate/@Certificate" />
				</text>
			</xsl:if>
		</rect>
		
		<xsl:apply-templates select="diag:Revocations/diag:CertificateRevocation"/>
	</xsl:template>
	
	<xsl:template match="diag:CertificateRevocation">
		<xsl:variable name="revocationId"><xsl:value-of select="@Revocation" /></xsl:variable>
		<xsl:variable name="certificateId"><xsl:value-of select="../../@Id" /></xsl:variable>
		
		<svg class="svg-certificate-revocation">
			<title>
				<xsl:value-of select="$revocationId" />
			</title>		

			<text class="certificate-id" style="display:none">
				<xsl:value-of select="$certificateId" />
			</text>

			<xsl:choose>
				<xsl:when test="diag:RevocationDate">
					<text class="revocation-reason">
						<xsl:value-of select="diag:Reason" />
					</text>		
					<text class="revocation-date date" style="display:none">
						<xsl:value-of select="diag:RevocationDate" />
					</text>			
  					<use href="#revocation-symbol" class="revoked" />
				</xsl:when>
				<xsl:otherwise>
					<text class="production-date date" style="display:none">
						<xsl:value-of select="//diag:Revocation[@Id=$revocationId]/diag:ProductionDate" />
					</text>		
  					<use href="#revocation-symbol" class="not-revoked" />
				</xsl:otherwise>
			</xsl:choose>
		</svg>
	</xsl:template>
 
</xsl:stylesheet>
