<?xml version="1.0" encoding="UTF-8" ?>
<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:dss="http://dss.esig.europa.eu/validation/diagnostic">
                
	<xsl:output method="html" encoding="utf-8" indent="yes" omit-xml-declaration="yes" />

    <xsl:template match="/dss:SimpleReport">
	    <xsl:apply-templates/>
	    <xsl:call-template name="documentInformation"/>
    </xsl:template>


    <xsl:template match="dss:DocumentName"/>
    <xsl:template match="dss:SignatureFormat"/>
    <xsl:template match="dss:SignaturesCount"/>
    <xsl:template match="dss:ValidSignaturesCount"/>

    <xsl:template match="dss:Policy">
    	<dl>
    		<xsl:attribute name="class">dl-horizontal</xsl:attribute>
            <dt>Validation Policy:</dt>
            <dd><xsl:value-of select="dss:PolicyName"/></dd>
            <dd><small><xsl:value-of select="dss:PolicyDescription"/></small></dd>
		</dl>
    </xsl:template>

    <xsl:template match="dss:ValidationTime"/>

    <xsl:template match="dss:Signature">
    
        <xsl:variable name="indicationText" select="dss:Indication/text()"/>
        <xsl:variable name="indicationCssClass">
        	<xsl:choose>
				<xsl:when test="$indicationText='VALID'">text-success</xsl:when>
				<xsl:when test="$indicationText='INDETERMINATE'">text-warning</xsl:when>
				<xsl:when test="$indicationText='INVALID'">text-danger</xsl:when>
			</xsl:choose>
        </xsl:variable>
        
        <dl>
    		<xsl:attribute name="class">dl-horizontal</xsl:attribute>
            <dt>Indication:</dt>
			<dd>
				<xsl:attribute name="class"><xsl:value-of select="$indicationCssClass" /></xsl:attribute>
				<xsl:choose>
					<xsl:when test="$indicationText='VALID'">
						<span>
							<xsl:attribute name="class">glyphicon glyphicon-ok-sign</xsl:attribute>
						</span>
					</xsl:when>
					<xsl:when test="$indicationText='INDETERMINATE'">
						<span>
							<xsl:attribute name="class">glyphicon glyphicon-question-sign</xsl:attribute>
						</span>
					</xsl:when>
					<xsl:when test="$indicationText='INVALID'">
						<span>
							<xsl:attribute name="class">glyphicon glyphicon-remove-sign</xsl:attribute>
						</span>
					</xsl:when>
				</xsl:choose>
	
				<xsl:text> </xsl:text>
				<xsl:value-of select="dss:Indication" />
			</dd>
        </dl>            
        
        <dl>
    		<xsl:attribute name="class">dl-horizontal</xsl:attribute>
            <dt>Signature Level:</dt>
            <dd>
                <xsl:value-of select="dss:SignatureLevel"/>
        	</dd>
        </dl>
        
        <xsl:apply-templates select="dss:SubIndication">
            <xsl:with-param name="indicationClass" select="$indicationCssClass"/>
        </xsl:apply-templates>
	    <xsl:apply-templates select="dss:Error">
		    <xsl:with-param name="indicationClass" select="$indicationCssClass"/>
	    </xsl:apply-templates>
	    <xsl:apply-templates select="dss:Warning">
		    <xsl:with-param name="indicationClass" select="$indicationCssClass"/>
	    </xsl:apply-templates>
        <xsl:apply-templates select="dss:Info">
            <xsl:with-param name="indicationClass" select="$indicationCssClass"/>
        </xsl:apply-templates>
        
        
        <dl>
    		<xsl:attribute name="class">dl-horizontal</xsl:attribute>
            <dt>Signature ID:</dt>
            <dd><xsl:value-of select="@Id"/></dd>
        </dl>
        
        <dl>
    		<xsl:attribute name="class">dl-horizontal</xsl:attribute>
            <dt>Signature format:</dt>
            <dd><xsl:value-of select="@SignatureFormat"/></dd>
        </dl>
        
        <dl>
    		<xsl:attribute name="class">dl-horizontal</xsl:attribute>
            <dt>Signed by:</dt>
            <dd><xsl:value-of select="dss:SignedBy"/></dd>
        </dl>
        
        <dl>
    		<xsl:attribute name="class">dl-horizontal</xsl:attribute>
            <dt>On claimed time:</dt>
            <dd><xsl:value-of select="dss:SigningTime"/></dd>
            <dd>The validation of the signature, of its supporting certificates and of the related certification path has been performed from this reference time.</dd>
        </dl>
        
        <dl>
    		<xsl:attribute name="class">dl-horizontal</xsl:attribute>
            <dt>Signature position:</dt>
            <dd><xsl:value-of select="count(preceding-sibling::dss:Signature) + 1"/> out of <xsl:value-of select="count(ancestor::*/dss:Signature)"/></dd>
        </dl>
        
        <xsl:for-each select="./dss:SignatureScopes/dss:SignatureScope">
	        <dl>
	    		<xsl:attribute name="class">dl-horizontal</xsl:attribute>
	            <dt>Signature scope:</dt>
	            <dd><xsl:value-of select="@name"/> (<xsl:value-of select="@scope"/>)</dd>
	            <dd><xsl:value-of select="."/></dd>
	        </dl>
        </xsl:for-each>
    </xsl:template>

	<xsl:template match="dss:SubIndication">
		<xsl:param name="indicationClass" />
		<dl>
    		<xsl:attribute name="class">dl-horizontal</xsl:attribute>
			<dt></dt>
			<dd>
				<xsl:attribute name="class"><xsl:value-of select="$indicationClass" /></xsl:attribute>
				<xsl:value-of select="." />
			</dd>
		</dl>
	</xsl:template>

	<xsl:template match="dss:Error">
		<xsl:param name="indicationClass" />
		<dl>
    		<xsl:attribute name="class">dl-horizontal</xsl:attribute>
			<dt></dt>
			<dd>
				<xsl:attribute name="class"><xsl:value-of select="$indicationClass" /></xsl:attribute>
				<xsl:variable name="txt" select="concat(name(@*[not(name()='NameId')][1]),'=',@*[not(name()='NameId')],' / ')"/>
				<xsl:variable name="ntxt">
					<xsl:call-template name="string-replace-all">
						<xsl:with-param name="text" select="$txt" />
						<xsl:with-param name="replace" select="'= /'" />
						<xsl:with-param name="by" select="''"/>
					</xsl:call-template>
				</xsl:variable>
				<xsl:value-of select="$ntxt"/>
				<xsl:apply-templates/>
			</dd>
		</dl>
	</xsl:template>

	<xsl:template match="dss:Warning">
		<xsl:param name="indicationClass" />
		<dl>
    		<xsl:attribute name="class">dl-horizontal</xsl:attribute>
			<dt></dt>
			<dd>
				<xsl:attribute name="class"><xsl:value-of select="$indicationClass" /></xsl:attribute>
				<xsl:variable name="txt" select="concat(name(@*[not(name()='NameId')][1]),'=',@*[not(name()='NameId')],' / ')"/>
				<xsl:variable name="ntxt">
					<xsl:call-template name="string-replace-all">
						<xsl:with-param name="text" select="$txt" />
						<xsl:with-param name="replace" select="'= /'" />
						<xsl:with-param name="by" select="''"/>
					</xsl:call-template>
				</xsl:variable>
				<xsl:value-of select="$ntxt"/>
				<xsl:apply-templates/>
			</dd>
		</dl>
	</xsl:template>

	<xsl:template match="dss:Info">
		<xsl:param name="indicationClass" />
		<dl>
    		<xsl:attribute name="class">dl-horizontal</xsl:attribute>
			<dt></dt>
			<dd>
				<xsl:attribute name="class"><xsl:value-of select="$indicationClass" /></xsl:attribute>
				<xsl:variable name="txt" select="concat(' - I: ',name(@*[not(name()='NameId')][1]),'=',@*[not(name()='NameId')],' / ')"/>
				<xsl:variable name="ntxt">
					<xsl:call-template name="string-replace-all">
						<xsl:with-param name="text" select="$txt" />
						<xsl:with-param name="replace" select="'= /'" />
						<xsl:with-param name="by" select="''"/>
					</xsl:call-template>
				</xsl:variable>
				<xsl:value-of select="$ntxt"/>
				<xsl:apply-templates/>
			</dd>
		</dl>
	</xsl:template>

	<xsl:template name="documentInformation">
		<h3>Document Information</h3>
		<dl>
    		<xsl:attribute name="class">dl-horizontal</xsl:attribute>
            <dt>Signatures status:</dt>
            <dd>
                <xsl:choose>
                    <xsl:when test="dss:ValidSignaturesCount = dss:SignaturesCount">
                        <xsl:attribute name="class">text-success</xsl:attribute>
                    </xsl:when>
                    <xsl:otherwise>
                        <xsl:attribute name="class">text-warning</xsl:attribute>
                    </xsl:otherwise>
                </xsl:choose>
                <xsl:value-of select="dss:ValidSignaturesCount"/> valid signatures, out of <xsl:value-of select="dss:SignaturesCount"/>
            </dd>
        </dl>
        <dl>
    		<xsl:attribute name="class">dl-horizontal</xsl:attribute>
            <dt>Document name:</dt>
            <dd><xsl:value-of select="dss:DocumentName"/></dd>
        </dl>
    </xsl:template>

	<xsl:template name="string-replace-all">
		<xsl:param name="text" />
		<xsl:param name="replace" />
		<xsl:param name="by" />
		<xsl:choose>
			<xsl:when test="contains($text, $replace)">
				<xsl:value-of select="substring-before($text,$replace)" />
				<xsl:value-of select="$by" />
				<xsl:call-template name="string-replace-all">
					<xsl:with-param name="text"
					                select="substring-after($text,$replace)" />
					<xsl:with-param name="replace" select="$replace" />
					<xsl:with-param name="by" select="$by" />
				</xsl:call-template>
			</xsl:when>
			<xsl:otherwise>
				<xsl:value-of select="$text" />
			</xsl:otherwise>
		</xsl:choose>
	</xsl:template>
</xsl:stylesheet>
