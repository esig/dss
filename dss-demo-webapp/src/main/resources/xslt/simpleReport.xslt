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
    <xsl:template match="dss:ValidationTime"/>

    <xsl:template match="dss:Policy">
		<div>
    		<xsl:attribute name="class">panel panel-primary</xsl:attribute>
    		<div>
    			<xsl:attribute name="class">panel-heading</xsl:attribute>
	    		<xsl:attribute name="data-target">#collapsePolicy</xsl:attribute>
		       	<xsl:attribute name="data-toggle">collapse</xsl:attribute>
    			Validation Policy : <xsl:value-of select="dss:PolicyName"/>
	        </div>
    		<div>
    			<xsl:attribute name="class">panel-body collapse</xsl:attribute>
	        	<xsl:attribute name="id">collapsePolicy</xsl:attribute>
	        	<p>
	        		<xsl:value-of select="dss:PolicyDescription"/>
	        	</p>
    		</div>
    	</div>
    </xsl:template>

    <xsl:template match="dss:Signature">
        <xsl:variable name="indicationText" select="dss:Indication/text()"/>
        <xsl:variable name="idSig" select="@Id" />
        <xsl:variable name="indicationCssClass">
        	<xsl:choose>
				<xsl:when test="$indicationText='VALID'">success</xsl:when>
				<xsl:when test="$indicationText='INDETERMINATE'">warning</xsl:when>
				<xsl:when test="$indicationText='INVALID'">danger</xsl:when>
			</xsl:choose>
        </xsl:variable>
        
        <div>
    		<xsl:attribute name="class">panel panel-<xsl:value-of select="$indicationCssClass" /></xsl:attribute>
    		<div>
    			<xsl:attribute name="class">panel-heading</xsl:attribute>
	    		<xsl:attribute name="data-target">#collapseSig<xsl:value-of select="$idSig" /></xsl:attribute>
		       	<xsl:attribute name="data-toggle">collapse</xsl:attribute>
    			Signature <xsl:value-of select="$idSig" />
	        </div>
    		<div>
    			<xsl:attribute name="class">panel-body collapse</xsl:attribute>
				<xsl:attribute name="id">collapseSig<xsl:value-of select="$idSig" /></xsl:attribute>
			
				<dl>
					<xsl:attribute name="class">dl-horizontal</xsl:attribute>
					<dt>Indication:</dt>
					<dd>
						<xsl:attribute name="class">text-<xsl:value-of select="$indicationCssClass" /></xsl:attribute>
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
				
    		</div>
    	</div>
    </xsl:template>

	<xsl:template match="dss:SubIndication|dss:Error|dss:Warning|dss:Info">
		<xsl:param name="indicationClass" />
		<dl>
    		<xsl:attribute name="class">dl-horizontal</xsl:attribute>
			<dt></dt>
			<dd>
				<xsl:attribute name="class">text-<xsl:value-of select="$indicationClass" /></xsl:attribute>
				<xsl:value-of select="." />
			</dd>
		</dl>
	</xsl:template>

    <xsl:template name="documentInformation">
		<div>
    		<xsl:attribute name="class">panel panel-primary</xsl:attribute>
    		<div>
    			<xsl:attribute name="class">panel-heading</xsl:attribute>
	    		<xsl:attribute name="data-target">#collapseInfo</xsl:attribute>
		       	<xsl:attribute name="data-toggle">collapse</xsl:attribute>
    			Document Information
	        </div>
    		<div>
    			<xsl:attribute name="class">panel-body collapse</xsl:attribute>
	        	<xsl:attribute name="id">collapseInfo</xsl:attribute>
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
    		</div>
    	</div>
    </xsl:template>
</xsl:stylesheet>
