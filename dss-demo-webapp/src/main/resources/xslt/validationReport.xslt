<?xml version="1.0" encoding="UTF-8" ?>
<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:dss="http://dss.esig.europa.eu/validation/diagnostic">

	<xsl:output method="html" encoding="utf-8" indent="yes" omit-xml-declaration="yes" />

    <xsl:template match="/dss:ValidationData">
	    <xsl:apply-templates/>
    </xsl:template>

    <xsl:template match="dss:BasicBuildingBlocks">    
    	<xsl:choose>
    		<xsl:when test="ancestor::dss:Timestamp">
    			<xsl:apply-templates/>
    		</xsl:when>
    		<xsl:otherwise>  
		        <div>
		    		<xsl:attribute name="class">panel panel-primary</xsl:attribute>
		    		<div>
		    			<xsl:attribute name="class">panel-heading</xsl:attribute>
			    		<xsl:attribute name="data-target">#collapseBasicBuildingBlocks</xsl:attribute>
				       	<xsl:attribute name="data-toggle">collapse</xsl:attribute>
		    			Basic Building Blocks
			        </div>
					<xsl:if test="count(child::*[name(.)!='Conclusion']) &gt; 0">
			    		<div>
			    			<xsl:attribute name="class">panel-body collapse</xsl:attribute>
				        	<xsl:attribute name="id">collapseBasicBuildingBlocks</xsl:attribute>
				        	<xsl:apply-templates/>
			    		</div>
		    		</xsl:if>
		    	</div>
    		</xsl:otherwise>
    	</xsl:choose>
    </xsl:template>

	<xsl:template match="dss:BasicValidationData">
		<div>
			<xsl:attribute name="class">panel panel-primary</xsl:attribute>
			<div>
				<xsl:attribute name="class">panel-heading</xsl:attribute>
				<xsl:attribute name="data-target">#collapseBasicValidationData</xsl:attribute>
				<xsl:attribute name="data-toggle">collapse</xsl:attribute>
				Basic Validation Data
			</div>
			<xsl:if test="count(child::*[name(.)!='Conclusion']) &gt; 0">
				<div>
					<xsl:attribute name="class">panel-body collapse</xsl:attribute>
					<xsl:attribute name="id">collapseBasicValidationData</xsl:attribute>
					<xsl:apply-templates />
				</div>
			</xsl:if>
		</div>
	</xsl:template>

    <xsl:template match="dss:TimestampValidationData">
    	<div>
    		<xsl:attribute name="class">panel panel-primary</xsl:attribute>
    		<div>
    			<xsl:attribute name="class">panel-heading</xsl:attribute>
	    		<xsl:attribute name="data-target">#collapseTimestampValidationData</xsl:attribute>
		       	<xsl:attribute name="data-toggle">collapse</xsl:attribute>
    			Timestamp Validation Data
	        </div>
			<xsl:if test="count(child::*[name(.)!='Conclusion']) &gt; 0">
	    		<div>
	    			<xsl:attribute name="class">panel-body collapse</xsl:attribute>
		        	<xsl:attribute name="id">collapseTimestampValidationData</xsl:attribute>
		        	<xsl:apply-templates/>
	    		</div>
	    	</xsl:if>
    	</div>
    </xsl:template>

    <xsl:template match="dss:AdESTValidationData">
    	<div>
    		<xsl:attribute name="class">panel panel-primary</xsl:attribute>
    		<div>
    			<xsl:attribute name="class">panel-heading</xsl:attribute>
	    		<xsl:attribute name="data-target">#collapseAdESTValidationData</xsl:attribute>
		       	<xsl:attribute name="data-toggle">collapse</xsl:attribute>
    			AdES-T Validation Data
	        </div>
			<xsl:if test="count(child::*[name(.)!='Conclusion']) &gt; 0">
	    		<div>
	    			<xsl:attribute name="class">panel-body collapse</xsl:attribute>
		        	<xsl:attribute name="id">collapseAdESTValidationData</xsl:attribute>
		        	<xsl:apply-templates/>
	    		</div>
	    	</xsl:if>
    	</div>
    </xsl:template>

    <xsl:template match="dss:LongTermValidationData">
    	<div>
    		<xsl:attribute name="class">panel panel-primary</xsl:attribute>
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

    <xsl:template match="dss:Signature">
    	<xsl:variable name="uid">
    		<xsl:value-of select="generate-id(.)" />
    	</xsl:variable>
    
    	<xsl:variable name="indicationText" select="dss:Conclusion/dss:Indication/text()"/>
        <xsl:variable name="indicationCssClass">
        	<xsl:choose>
				<xsl:when test="$indicationText='VALID'">success</xsl:when>
				<xsl:when test="$indicationText='INDETERMINATE'">warning</xsl:when>
				<xsl:when test="$indicationText='INVALID'">danger</xsl:when>
				<xsl:otherwise>default</xsl:otherwise>
			</xsl:choose>
        </xsl:variable>
        
        <div>
    		<xsl:attribute name="class">panel panel-<xsl:value-of select="$indicationCssClass" /></xsl:attribute>
    		<div>
    			<xsl:attribute name="class">panel-heading</xsl:attribute>
	    		<xsl:attribute name="data-target">#collapseSig<xsl:value-of select="$uid" /></xsl:attribute>
		       	<xsl:attribute name="data-toggle">collapse</xsl:attribute>
		       	
		       	<xsl:if test="string-length(dss:Conclusion/dss:SubIndication) &gt; 0">
			        <span>
			        	<xsl:attribute name="class">label label-<xsl:value-of select="$indicationCssClass" /> pull-right</xsl:attribute>
			        	<xsl:if test="string-length(dss:Conclusion/dss:Error) &gt; 0">
			        		<xsl:attribute name="title"><xsl:value-of select="dss:Conclusion/dss:Error"/></xsl:attribute>
			        	</xsl:if>
			        	<xsl:if test="string-length(dss:Conclusion/dss:Warning) &gt; 0">
			        		<xsl:attribute name="title"><xsl:value-of select="dss:Conclusion/dss:Warning"/></xsl:attribute>
			        	</xsl:if>
			        	<xsl:value-of select="dss:Conclusion/dss:SubIndication"/>
		        	</span>
		        </xsl:if>
		       	
    			Signature <xsl:value-of select="@Id" />
	        </div>
	        
		    <xsl:if test="count(child::*[name(.)!='Conclusion']) &gt; 0">
	    		<div>
	    			<xsl:attribute name="class">panel-body collapse</xsl:attribute>
					<xsl:attribute name="id">collapseSig<xsl:value-of select="$uid" /></xsl:attribute>
					<xsl:apply-templates/>
			    </div>
		    </xsl:if>
		</div>
    </xsl:template>
    
	<xsl:template match="dss:Timestamp">
		<xsl:variable name="uid">
    		<xsl:value-of select="generate-id(.)" />
    	</xsl:variable>
    
    	<xsl:variable name="indicationText" select="dss:BasicBuildingBlocks/dss:Conclusion/dss:Indication/text()"/>
        <xsl:variable name="indicationCssClass">
        	<xsl:choose>
				<xsl:when test="$indicationText='VALID'">success</xsl:when>
				<xsl:when test="$indicationText='INDETERMINATE'">warning</xsl:when>
				<xsl:when test="$indicationText='INVALID'">danger</xsl:when>
				<xsl:otherwise>default</xsl:otherwise>
			</xsl:choose>
        </xsl:variable>
        
        <div>
    		<xsl:attribute name="class">panel panel-<xsl:value-of select="$indicationCssClass" /></xsl:attribute>
    		<div>
    			<xsl:attribute name="class">panel-heading</xsl:attribute>
	    		<xsl:attribute name="data-target">#collapseSig<xsl:value-of select="$uid" /></xsl:attribute>
		       	<xsl:attribute name="data-toggle">collapse</xsl:attribute>
		       	
		       	<xsl:if test="string-length(dss:BasicBuildingBlocks/dss:Conclusion/dss:SubIndication) &gt; 0">
			        <span>
			        	<xsl:attribute name="class">label label-<xsl:value-of select="$indicationCssClass" /> pull-right</xsl:attribute>
			        	<xsl:if test="string-length(dss:BasicBuildingBlocks/dss:Conclusion/dss:Error) &gt; 0">
			        		<xsl:attribute name="title"><xsl:value-of select="dss:BasicBuildingBlocks/dss:Conclusion/dss:Error"/></xsl:attribute>
			        	</xsl:if>
			        	<xsl:if test="string-length(dss:BasicBuildingBlocks/dss:Conclusion/dss:Warning) &gt; 0">
			        		<xsl:attribute name="title"><xsl:value-of select="dss:BasicBuildingBlocks/dss:Conclusion/dss:Warning"/></xsl:attribute>
			        	</xsl:if>
			        	<xsl:value-of select="dss:BasicBuildingBlocks/dss:Conclusion/dss:SubIndication"/>
		        	</span>
		        </xsl:if>
		        
				Timestamp <xsl:value-of select="@Id" /> :	
			</div>
			
			<xsl:if test="count(child::*[name(.)!='Conclusion']) &gt; 0">
	    		<div>
	    			<xsl:attribute name="class">panel-body collapse</xsl:attribute>
					<xsl:attribute name="id">collapseSig<xsl:value-of select="$uid" /></xsl:attribute>

					<div>
						<xsl:attribute name="class">row</xsl:attribute>
						<div>
							<xsl:attribute name="class">col-md-6</xsl:attribute>
							<strong>Type :</strong> 
						</div>
						<div>
							<xsl:attribute name="class">col-md-6</xsl:attribute>
							<span>
			        			<xsl:attribute name="class">label label-primary</xsl:attribute>
			        			<xsl:value-of select="@Type" />
			        		</span>
						</div>
					</div>

					<xsl:apply-templates/>
			    </div>
		    </xsl:if>
		</div>
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
	        	<xsl:if test="string-length($Conclusion/dss:Error) &gt; 0">
	        		<xsl:attribute name="title"><xsl:value-of select="$Conclusion/dss:Error"/></xsl:attribute>
	        	</xsl:if>
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
							<xsl:attribute name="title">OK</xsl:attribute>
						</span>
					</xsl:when>
					<xsl:when test="$statusText='NOT OK'">
						<span>
							<xsl:attribute name="class">glyphicon glyphicon glyphicon-remove-sign text-danger</xsl:attribute>
							<xsl:attribute name="title"><xsl:value-of select="dss:Error" /></xsl:attribute>
						</span>
					</xsl:when>
					<xsl:when test="$statusText='WARNING'">
						<span>
							<xsl:attribute name="class">glyphicon glyphicon-exclamation-sign text-warning</xsl:attribute>
							<xsl:attribute name="title"><xsl:value-of select="dss:Warning" /></xsl:attribute>
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

    <xsl:template match="dss:Constraint/dss:Info"/>

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

</xsl:stylesheet>
