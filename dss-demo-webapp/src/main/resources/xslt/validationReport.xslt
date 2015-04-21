<?xml version="1.0" encoding="UTF-8" ?>
<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:dss="http://dss.esig.europa.eu/validation/diagnostic">

	<xsl:output method="html" encoding="utf-8" indent="yes" omit-xml-declaration="yes" />

    <xsl:template match="/dss:ValidationData">
	    <xsl:apply-templates/>
    </xsl:template>

    <xsl:template match="dss:BasicBuildingBlocks">      
        <div>
    		<xsl:attribute name="class">panel panel-default</xsl:attribute>
    		<div>
    			<xsl:attribute name="class">panel-heading</xsl:attribute>
	    		<xsl:attribute name="data-target">#collapseBasicBuildingBlocks</xsl:attribute>
		       	<xsl:attribute name="data-toggle">collapse</xsl:attribute>
    			Basic Building Blocks
	        </div>
    		<div>
    			<xsl:attribute name="class">panel-body collapse</xsl:attribute>
	        	<xsl:attribute name="id">collapseBasicBuildingBlocks</xsl:attribute>
	        	<xsl:apply-templates/>
    		</div>
    	</div>
    </xsl:template>

    <xsl:template match="dss:BasicValidationData">
    	<div>
    		<xsl:attribute name="class">panel panel-default</xsl:attribute>
    		<div>
    			<xsl:attribute name="class">panel-heading</xsl:attribute>
	    		<xsl:attribute name="data-target">#collapseBasicValidationData</xsl:attribute>
		       	<xsl:attribute name="data-toggle">collapse</xsl:attribute>
    			Basic Validation Data
	        </div>
    		<div>
    			<xsl:attribute name="class">panel-body collapse</xsl:attribute>
	        	<xsl:attribute name="id">collapseBasicValidationData</xsl:attribute>
	        	<xsl:apply-templates/>
    		</div>
    	</div>
    </xsl:template>

    <xsl:template match="dss:TimestampValidationData">
    	<div>
    		<xsl:attribute name="class">panel panel-default</xsl:attribute>
    		<div>
    			<xsl:attribute name="class">panel-heading</xsl:attribute>
	    		<xsl:attribute name="data-target">#collapseTimestampValidationData</xsl:attribute>
		       	<xsl:attribute name="data-toggle">collapse</xsl:attribute>
    			Timestamp Validation Data
	        </div>
    		<div>
    			<xsl:attribute name="class">panel-body collapse</xsl:attribute>
	        	<xsl:attribute name="id">collapseTimestampValidationData</xsl:attribute>
	        	<xsl:apply-templates/>
    		</div>
    	</div>
    </xsl:template>

    <xsl:template match="dss:AdESTValidationData">
    	<div>
    		<xsl:attribute name="class">panel panel-default</xsl:attribute>
    		<div>
    			<xsl:attribute name="class">panel-heading</xsl:attribute>
	    		<xsl:attribute name="data-target">#collapseAdESTValidationData</xsl:attribute>
		       	<xsl:attribute name="data-toggle">collapse</xsl:attribute>
    			AdES-T Validation Data
	        </div>
    		<div>
    			<xsl:attribute name="class">panel-body collapse</xsl:attribute>
	        	<xsl:attribute name="id">collapseAdESTValidationData</xsl:attribute>
	        	<xsl:apply-templates/>
    		</div>
    	</div>
    </xsl:template>

    <xsl:template match="dss:LongTermValidationData">
    	<div>
    		<xsl:attribute name="class">panel panel-default</xsl:attribute>
    		<div>
    			<xsl:attribute name="class">panel-heading</xsl:attribute>
	    		<xsl:attribute name="data-target">#collapseLongTermValidationData</xsl:attribute>
		       	<xsl:attribute name="data-toggle">collapse</xsl:attribute>
    			Long Term Validation Data
	        </div>
    		<div>
    			<xsl:attribute name="class">panel-body collapse</xsl:attribute>
	        	<xsl:attribute name="id">collapseLongTermValidationData</xsl:attribute>
	        	<xsl:apply-templates/>
    		</div>
    	</div>
    </xsl:template>
<!-- 
    <xsl:template match="dss:AdESTValidationData/dss:Signature|dss:LongTermValidationData/dss:Signature">
        <h3 class="signature-title" xml:space="preserve">Signature
            <xsl:value-of select="@Id"/>:
            <xsl:call-template name="signature-conclusion">
                <xsl:with-param name="Conclusion" select="dss:Conclusion" />
            </xsl:call-template>
        </h3>
        <div class="signature-content">
            <xsl:apply-templates/>
        </div>
    </xsl:template>


    <xsl:template match="dss:TimestampValidationData/dss:Signature">
        <h3 class="signature-title" xml:space="preserve">Signature
            <xsl:value-of select="@Id"/>
        </h3>
        <div class="timestamp">
            <xsl:apply-templates/>
        </div>
    </xsl:template>
 -->
    <xsl:template match="dss:TimestampValidationData/dss:Signature/dss:Timestamp">
        <h4 class="signature-title" xml:space="preserve">Timestamp
            <span xml:space="preserve"><xsl:value-of select="@Id"/> / [<xsl:value-of select="@Type" />]</span>:
            <xsl:call-template name="signature-conclusion">
                <xsl:with-param name="Conclusion" select="dss:BasicBuildingBlocks/dss:Conclusion"/>
            </xsl:call-template>
        </h4>
        <xsl:if test="count(child::*[name(.)!='Conclusion']) &gt; 0">
            <div class="signature-content">
                <xsl:apply-templates/>
            </div>
        </xsl:if>
    </xsl:template>

    <xsl:template match="dss:Signature">
	    <div>
	    	<xsl:attribute name="class">row</xsl:attribute>
	    	<div>
	    		<xsl:attribute name="class">col-md-6</xsl:attribute>
	    		<strong>
	    			Signature <xsl:value-of select="@Id"/>:
	    		</strong>
	    	</div>
	    	<div>
	    		<xsl:attribute name="class">col-md-6</xsl:attribute>
    			<xsl:call-template name="signature-conclusion">
                	<xsl:with-param name="Conclusion" select="dss:Conclusion" />
            	</xsl:call-template>
    		</div>
    	</div>
    	<xsl:if test="count(child::*[name(.)!='Conclusion']) &gt; 0">
            <div class="signature-content">
                <xsl:apply-templates/>
            </div>
        </xsl:if>
    </xsl:template>

    <xsl:template name="signature-conclusion">
        <xsl:param name="Conclusion"/>
        
        <xsl:variable name="indicationText" select="$Conclusion/dss:Indication"/>
        <xsl:variable name="indicationCssClass">
        	<xsl:choose>
				<xsl:when test="$indicationText='VALID'">label-success</xsl:when>
				<xsl:when test="$indicationText='INDETERMINATE'">label-warning</xsl:when>
				<xsl:when test="$indicationText='INVALID'">label-danger</xsl:when>
			</xsl:choose>
        </xsl:variable>
        
        <span>
        	<xsl:attribute name="class">label <xsl:value-of select="$indicationCssClass" /></xsl:attribute>
            <xsl:value-of select="$Conclusion/dss:Indication"/>
        </span>
        
        <xsl:if test="string-length($Conclusion/dss:SubIndication) &gt; 0">
			<xsl:text> </xsl:text>
	        <span>
	        	<xsl:attribute name="class">label <xsl:value-of select="$indicationCssClass" /></xsl:attribute>
	        	<xsl:value-of select="$Conclusion/dss:SubIndication"/>
        	</span>
        </xsl:if>
    </xsl:template>

    <xsl:template match="dss:ISC|dss:VCI|dss:CV|dss:SAV|dss:XCV">
		<div>
			<xsl:attribute name="class">row</xsl:attribute>
			<div>
				<xsl:attribute name="class">col-md-6</xsl:attribute>
				<strong>
					<xsl:choose>
						<xsl:when test="name(.) = 'ISC'">
							Identification of the signing certificate
						</xsl:when>
						<xsl:when test="name(.) = 'VCI'">
							Validation Context Initialization
						</xsl:when>
						<xsl:when test="name(.) = 'CV'">
							Cryptographic Verification
						</xsl:when>
						<xsl:when test="name(.) = 'SAV'">
							Signature Acceptance Validation
						</xsl:when>
						<xsl:when test="name(.) = 'XCV'">
							X509 Certificate Validation
						</xsl:when>
						<xsl:otherwise>
							<xsl:value-of select="name(.)" />
						</xsl:otherwise>
					</xsl:choose>
					:
				</strong>
			</div>
			<div>
				<xsl:attribute name="class">col-md-6</xsl:attribute>
				<xsl:call-template name="signature-conclusion">
					<xsl:with-param name="Conclusion" select="dss:Conclusion" />
				</xsl:call-template>
			</div>
		</div>
		<xsl:apply-templates />
    </xsl:template>


    <xsl:template match="dss:Constraint">
	    <div>
	    	<xsl:attribute name="class">row</xsl:attribute>
	    	<div>
	    		<xsl:attribute name="class">col-md-6</xsl:attribute>
				<xsl:value-of select="dss:Name"/>
	    	</div>
	    	<div>
	    		<xsl:attribute name="class">col-md-6</xsl:attribute>
	        	<xsl:variable name="statusText" select="dss:Status"/>
	        	<xsl:choose>
					<xsl:when test="$statusText='OK'">
						<span>
							<xsl:attribute name="class">glyphicon glyphicon-ok-sign text-success</xsl:attribute>
							<xsl:attribute name="title">OK </xsl:attribute>
						</span>
					</xsl:when>
					<xsl:when test="$statusText='NOT OK'">
						<span>
							<xsl:attribute name="class">glyphicon glyphicon glyphicon-remove-sign text-danger</xsl:attribute>
							<xsl:attribute name="title">NOT OK </xsl:attribute>
						</span>
					</xsl:when>
					<xsl:otherwise>
						<span>
							<xsl:value-of select="dss:Status" />
						</span>
					</xsl:otherwise>
	    		</xsl:choose>
	    	</div>
	    </div>
        <xsl:apply-templates select="dss:Info"/>
    </xsl:template>

	<xsl:template match="dss:Info|dss:Warning|dss:Error">
		<div>
			<xsl:attribute name="class">row</xsl:attribute>
			<div>
				<xsl:attribute name="class">col-md-6</xsl:attribute>
				<xsl:value-of select="name(@*[not(name()='NameId')][1])" />
			</div>
			<div>
				<xsl:attribute name="class">col-md-6</xsl:attribute>
				<xsl:value-of select="@*[not(name()='NameId')]" />
				<xsl:text> </xsl:text>
				<xsl:apply-templates />
			</div>
		</div>
	</xsl:template>
  
	<xsl:template match="*">
		<xsl:comment>
			Ignored tag:
			<xsl:value-of select="name()" />
		</xsl:comment>
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
					<xsl:with-param name="text" select="substring-after($text,$replace)" />
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
