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

			<xsl:apply-templates select="diag:UsedCertificates/diag:Certificate"/>
			<xsl:apply-templates select="diag:UsedTimestamps/diag:Timestamp"/>
			
	    </svg>
	</xsl:template>
	
	<xsl:template match="diag:Certificate">
		<rect  width="200" height="10" fill="red">
			<xsl:attribute name="id"><xsl:value-of select="@Id" /></xsl:attribute>			
			<xsl:attribute name="data-not-before"><xsl:value-of select="diag:NotBefore" /></xsl:attribute>
			<xsl:attribute name="data-not-after"><xsl:value-of select="diag:NotAfter" /></xsl:attribute>	

			<xsl:apply-templates select="diag:Revocations/diag:CertificateRevocation"/>
		</rect>
	</xsl:template>
	
	<xsl:template match="diag:CertificateRevocation">
		<xsl:if test="diag:RevocationDate">
			<xsl:attribute name="data-revocation-reason"><xsl:value-of select="diag:Reason" /></xsl:attribute>		
			<xsl:attribute name="data-revocation-date"><xsl:value-of select="diag:RevocationDate" /></xsl:attribute>			
		</xsl:if>
	</xsl:template>
	
	<xsl:template match="diag:Timestamp">
		<rect  width="200" height="10" fill="green">
			<xsl:attribute name="id"><xsl:value-of select="@Id" /></xsl:attribute>
			<xsl:attribute name="production-time"><xsl:value-of select="diag:ProductionTime" /></xsl:attribute>
		</rect>
	</xsl:template>


  
</xsl:stylesheet>
