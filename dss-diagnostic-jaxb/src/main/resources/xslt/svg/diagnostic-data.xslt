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
	  <svg xmlns="http://www.w3.org/2000/svg" width="800" height="600">
	  
	  		<text class="svg-validation-time date">
				<xsl:value-of select="diag:ValidationDate" />
			</text>

			<xsl:apply-templates select="diag:Signatures/diag:Signature"/>
			<xsl:apply-templates select="diag:UsedTimestamps/diag:Timestamp"/>
			<xsl:apply-templates select="diag:UsedCertificates/diag:Certificate"/>
			<xsl:apply-templates select="diag:UsedRevocations/diag:Revocation"/>
			
	  </svg>
	</xsl:template>
	
	<xsl:template match="diag:Signature">
		<rect width="200" height="10" fill="blue" class="svg-signature">
			<xsl:attribute name="id"><xsl:value-of select="@Id" /></xsl:attribute>
			
			<text class="svg-claimed-signing-time date">
				<xsl:value-of select="diag:ClaimedSigningTime" />
			</text>
			
			<xsl:if test="diag:SigningCertificate/@Certificate">
				<text class="svg-signing-cert">
					<xsl:value-of select="diag:SigningCertificate/@Certificate" />
				</text>
			</xsl:if>
		</rect>
	</xsl:template>
	
	<xsl:template match="diag:Timestamp">
		<rect width="200" height="10" fill="green" class="svg-timestamp">
			<xsl:attribute name="id"><xsl:value-of select="@Id" /></xsl:attribute>
			
			<text class="svg-production-time date">
				<xsl:value-of select="diag:ProductionTime" />
			</text>
			
			<xsl:if test="diag:SigningCertificate/@Certificate">
				<text class="svg-signing-cert">
					<xsl:value-of select="diag:SigningCertificate/@Certificate" />
				</text>
			</xsl:if>
		</rect>
	</xsl:template>
	
	<xsl:template match="diag:Certificate">
		<rect width="200" height="10" fill="red" class="svg-certificate">
			<xsl:attribute name="id"><xsl:value-of select="@Id" /></xsl:attribute>			

			<text class="svg-not-before date">
				<xsl:value-of select="diag:NotBefore" />
			</text>
			<text class="svg-not-after date">
				<xsl:value-of select="diag:NotAfter" />
			</text>
			
			<xsl:if test="diag:SigningCertificate/@Certificate">
				<text class="svg-signing-cert">
					<xsl:value-of select="diag:SigningCertificate/@Certificate" />
				</text>
			</xsl:if>
		</rect>
		
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
		<xsl:if test="diag:RevocationDate">
			<xsl:attribute name="data-revocation-reason"><xsl:value-of select="diag:Reason" /></xsl:attribute>		
			<xsl:attribute name="data-revocation-date"><xsl:value-of select="diag:RevocationDate" /></xsl:attribute>			
		</xsl:if>
	</xsl:template>

 
</xsl:stylesheet>
