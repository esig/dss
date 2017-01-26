<?xml version="1.0" encoding="UTF-8" ?>
<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:dss="http://dss.esig.europa.eu/validation/detailed-report">

	<xsl:output method="html" encoding="utf-8" indent="yes" omit-xml-declaration="yes" />

    <xsl:template match="/dss:DetailedReport">
    	<div>
    		<xsl:attribute name="class">panel panel-primary</xsl:attribute>
	   		<div>
	   			<xsl:attribute name="class">panel-heading</xsl:attribute>
	    		<xsl:attribute name="data-target">#collapseETSI</xsl:attribute>
		       	<xsl:attribute name="data-toggle">collapse</xsl:attribute>
		       	Validation (ETSI EN 319 102-1)
		    </div>
		    <div>
				<xsl:attribute name="class">panel-body collapse in</xsl:attribute>
		        <xsl:attribute name="id">collapseETSI</xsl:attribute>
		        
				<xsl:apply-templates select="dss:Signatures"/>
				<xsl:apply-templates select="dss:BasicBuildingBlocks[@Type='SIGNATURE']"/>
				<xsl:apply-templates select="dss:BasicBuildingBlocks[@Type='COUNTER_SIGNATURE']"/>
				<xsl:apply-templates select="dss:BasicBuildingBlocks[@Type='TIMESTAMP']"/>
				<xsl:apply-templates select="dss:BasicBuildingBlocks[@Type='REVOCATION']"/>
			</div>
	    </div>
	    		
   		<xsl:apply-templates select="dss:QMatrixBlock"/>
    </xsl:template>

    <xsl:template match="dss:QMatrixBlock">
	    <div>
    		<xsl:attribute name="class">panel panel-primary</xsl:attribute>
	   		<div>
	   			<xsl:attribute name="class">panel-heading</xsl:attribute>
	    		<xsl:attribute name="data-target">#collapseQmatrix</xsl:attribute>
		       	<xsl:attribute name="data-toggle">collapse</xsl:attribute>
		       	Qualification (ETSI TS 119 172-4)
		    </div>
		    <div>
				<xsl:attribute name="class">panel-body collapse in</xsl:attribute>
		        <xsl:attribute name="id">collapseQmatrix</xsl:attribute>
		        
				<xsl:apply-templates select="dss:TLAnalysis" />
				<xsl:apply-templates select="dss:SignatureAnalysis" />
			</div>
		</div>
	</xsl:template>
	
	<xsl:template match="dss:Signatures">
		<div>
			<xsl:attribute name="class">panel panel-primary</xsl:attribute>
			<div>
				<xsl:attribute name="class">panel-heading</xsl:attribute>
				<xsl:attribute name="data-target">#collapseSignatureValidationData<xsl:value-of select="@Id"/></xsl:attribute>
				<xsl:attribute name="data-toggle">collapse</xsl:attribute>
				Signature <xsl:value-of select="@Id"/>
			</div>
			<xsl:if test="count(child::*[name(.)!='Conclusion']) &gt; 0">
				<div>
					<xsl:attribute name="class">panel-body collapse in</xsl:attribute>
					<xsl:attribute name="id">collapseSignatureValidationData<xsl:value-of select="@Id"/></xsl:attribute>
					<xsl:apply-templates select="dss:ValidationProcessBasicSignatures" />
					<xsl:call-template name="TimestampValidation" />
					<xsl:apply-templates select="dss:ValidationProcessLongTermData" />
					<xsl:apply-templates select="dss:ValidationProcessArchivalData" />
				</div>
			</xsl:if>
		</div>
	</xsl:template>
	
	<xsl:template match="dss:BasicBuildingBlocks">    
       <div>
       		<xsl:if test="@Id != ''">
       			<xsl:attribute name="id"><xsl:value-of select="@Id"/></xsl:attribute>
       		</xsl:if>
	   		<xsl:attribute name="class">panel panel-primary</xsl:attribute>
	   		<div>
	   			<xsl:attribute name="class">panel-heading</xsl:attribute>
	    		<xsl:attribute name="data-target">#collapseBasicBuildingBlocks<xsl:value-of select="@Id"/></xsl:attribute>
		       	<xsl:attribute name="data-toggle">collapse</xsl:attribute>
		       	<xsl:variable name="bbbId" select="@Id" />
		       	<xsl:variable name="bbbType">
		       		<xsl:choose>
		       			<xsl:when test="@Type = 'TIMESTAMP'"><xsl:value-of select="../dss:Signatures/dss:ValidationProcessTimestamps[@Id = $bbbId]/@Type"/></xsl:when>
		       			<xsl:otherwise><xsl:value-of select="@Type"/></xsl:otherwise>
		       		</xsl:choose>
		       	</xsl:variable>
	   			Basic Building Blocks <br/>
	   			<xsl:value-of select="$bbbType"/> (Id = <xsl:value-of select="@Id"/>)
	        </div>
			<xsl:if test="count(child::*[name(.)!='Conclusion']) &gt; 0">
	    		<div>
	    			<xsl:attribute name="class">panel-body collapse</xsl:attribute>
		        	<xsl:attribute name="id">collapseBasicBuildingBlocks<xsl:value-of select="@Id"/></xsl:attribute>
		        	<xsl:apply-templates/>
	    		</div>
	   		</xsl:if>
	   	</div>
    </xsl:template>

	<xsl:template match="dss:ValidationProcessBasicSignatures">
		<div>
			<xsl:variable name="indicationText" select="dss:Conclusion/dss:Indication/text()"/>
	        <xsl:variable name="indicationCssClass">
	        	<xsl:choose>
					<xsl:when test="$indicationText='PASSED'">success</xsl:when>
					<xsl:when test="$indicationText='INDETERMINATE'">warning</xsl:when>
					<xsl:when test="$indicationText='FAILED'">danger</xsl:when>
					<xsl:otherwise>default</xsl:otherwise>
				</xsl:choose>
	        </xsl:variable>
			<div>
				<xsl:attribute name="class">panel panel-<xsl:value-of select="$indicationCssClass" /></xsl:attribute>
	    		<div>
					<xsl:attribute name="class">panel-heading</xsl:attribute>
					<xsl:attribute name="data-target">#collapseBasicValidationData<xsl:value-of select="../@Id"/></xsl:attribute>
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
					Validation Process for Basic Signatures
				</div>
				<xsl:if test="count(child::*[name(.)!='Conclusion']) &gt; 0">
		    		<div>
		    			<xsl:attribute name="class">panel-body collapse in</xsl:attribute>
			        	<xsl:attribute name="id">collapseBasicValidationData<xsl:value-of select="../@Id"/></xsl:attribute>
			        	<xsl:apply-templates/>
		    		</div>
		    	</xsl:if>
			</div>
		</div>
	</xsl:template>

    <xsl:template name="TimestampValidation">
    	<xsl:variable name="TimestampValidationData" select="dss:ValidationProcessTimestamps" />
    	<xsl:if test="$TimestampValidationData != ''">
	    	<div>
	    		<xsl:attribute name="class">panel panel-default</xsl:attribute>
	    		<div>
	    			<xsl:attribute name="class">panel-heading</xsl:attribute>
		    		<xsl:attribute name="data-target">#collapseTimestampValidation<xsl:value-of select="@Id"/></xsl:attribute>
					<xsl:attribute name="data-toggle">collapse</xsl:attribute>
					Validation Process for Timestamps
				</div>
				<div>
					<xsl:attribute name="class">panel-body collapse in</xsl:attribute>
					<xsl:attribute name="id">collapseTimestampValidation<xsl:value-of select="@Id"/></xsl:attribute>
			    	<xsl:for-each select="dss:ValidationProcessTimestamps">
				    	<div>
				    		<xsl:variable name="indicationText" select="dss:Conclusion/dss:Indication/text()"/>
					        <xsl:variable name="indicationCssClass">
					        	<xsl:choose>
									<xsl:when test="$indicationText='PASSED'">success</xsl:when>
									<xsl:when test="$indicationText='INDETERMINATE'">warning</xsl:when>
									<xsl:when test="$indicationText='FAILED'">danger</xsl:when>
									<xsl:otherwise>default</xsl:otherwise>
								</xsl:choose>
					        </xsl:variable>
				    		<div>
				    			<xsl:attribute name="class">panel panel-<xsl:value-of select="$indicationCssClass" /></xsl:attribute>
					    		<div>
					    			<xsl:attribute name="class">panel-heading</xsl:attribute>
						    		<xsl:attribute name="data-target">#collapseTimestampValidationData<xsl:value-of select="@Id"/></xsl:attribute>
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
					    			<xsl:value-of select="@Type"/> Id = <xsl:value-of select="@Id"/>
						        </div>
								<xsl:if test="count(child::*[name(.)!='Conclusion']) &gt; 0">
						    		<div>
						    			<xsl:attribute name="class">panel-body collapse in</xsl:attribute>
							        	<xsl:attribute name="id">collapseTimestampValidationData<xsl:value-of select="@Id"/></xsl:attribute>
							        	<xsl:apply-templates/>
						    		</div>
						    	</xsl:if>
					    	</div>
				    	</div>
			    	</xsl:for-each>
		    	</div>
	    	</div>
    	</xsl:if>
    </xsl:template>
    
    <xsl:template match="dss:ValidationProcessArchivalData">
    	<div>
    		<xsl:variable name="indicationText" select="dss:Conclusion/dss:Indication/text()"/>
	        <xsl:variable name="indicationCssClass">
	        	<xsl:choose>
					<xsl:when test="$indicationText='PASSED'">success</xsl:when>
					<xsl:when test="$indicationText='INDETERMINATE'">warning</xsl:when>
					<xsl:when test="$indicationText='FAILED'">danger</xsl:when>
					<xsl:otherwise>default</xsl:otherwise>
				</xsl:choose>
	        </xsl:variable>
    		<div>
    			<xsl:attribute name="class">panel panel-<xsl:value-of select="$indicationCssClass" /></xsl:attribute>
	    		<div>
	    			<xsl:attribute name="class">panel-heading</xsl:attribute>
		    		<xsl:attribute name="data-target">#collapseArchivalValidationData<xsl:value-of select="../@Id"/></xsl:attribute>
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
	    			Validation Process for Signatures with Archival Data
		        </div>
				<xsl:if test="count(child::*[name(.)!='Conclusion']) &gt; 0">
		    		<div>
		    			<xsl:attribute name="class">panel-body collapse in</xsl:attribute>
			        	<xsl:attribute name="id">collapseArchivalValidationData<xsl:value-of select="../@Id"/></xsl:attribute>
			        	<xsl:apply-templates/>
		    		</div>
		    	</xsl:if>
	    	</div>
    	</div>
    </xsl:template>

    <xsl:template match="dss:ValidationProcessLongTermData">
    	<div>
	    	<xsl:variable name="indicationText" select="dss:Conclusion/dss:Indication/text()"/>
	        <xsl:variable name="indicationCssClass">
	        	<xsl:choose>
					<xsl:when test="$indicationText='PASSED'">success</xsl:when>
					<xsl:when test="$indicationText='INDETERMINATE'">warning</xsl:when>
					<xsl:when test="$indicationText='FAILED'">danger</xsl:when>
					<xsl:otherwise>default</xsl:otherwise>
				</xsl:choose>
	        </xsl:variable>
    		<div>
    			<xsl:attribute name="class">panel panel-<xsl:value-of select="$indicationCssClass" /></xsl:attribute>
	    		<div>
	    			<xsl:attribute name="class">panel-heading</xsl:attribute>
		    		<xsl:attribute name="data-target">#collapseLongTermValidationData<xsl:value-of select="../@Id"/></xsl:attribute>
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
	    			Validation Process for Signatures with Time and Signatures with Long-Term Validation Data
		        </div>
	    		<div>
	    			<xsl:attribute name="class">panel-body collapse in</xsl:attribute>
		        	<xsl:attribute name="id">collapseLongTermValidationData<xsl:value-of select="../@Id"/></xsl:attribute>
		        	<xsl:apply-templates/>
	    		</div>
    		</div>
    	</div>
    </xsl:template>
    
    <xsl:template match="dss:TLAnalysis">
    	<div>
       		<xsl:if test="@CountryCode != ''">
       			<xsl:attribute name="id"><xsl:value-of select="@CountryCode"/></xsl:attribute>
       		</xsl:if>
    		<xsl:variable name="indicationText" select="dss:Conclusion/dss:Indication/text()"/>
	        <xsl:variable name="indicationCssClass">
	        	<xsl:choose>
					<xsl:when test="$indicationText='PASSED'">success</xsl:when>
					<xsl:when test="$indicationText='INDETERMINATE'">warning</xsl:when>
					<xsl:when test="$indicationText='FAILED'">danger</xsl:when>
					<xsl:otherwise>default</xsl:otherwise>
				</xsl:choose>
	        </xsl:variable>
    		<div>
    			<xsl:attribute name="class">panel panel-<xsl:value-of select="$indicationCssClass" /></xsl:attribute>
	    		<div>
	    			<xsl:attribute name="class">panel-heading</xsl:attribute>
		    		<xsl:attribute name="data-target">#collapseTL<xsl:value-of select="@CountryCode"/></xsl:attribute>
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
	    			Trusted List <xsl:value-of select="@CountryCode"/>
		        </div>
				<xsl:if test="count(child::*[name(.)!='Conclusion']) &gt; 0">
		    		<div>
		    			<xsl:attribute name="class">panel-body collapse in</xsl:attribute>
			        	<xsl:attribute name="id">collapseTL<xsl:value-of select="@CountryCode"/></xsl:attribute>
			        	<xsl:apply-templates/>
		    		</div>
		    	</xsl:if>
	    	</div>
    	</div>
    </xsl:template>
    
    <xsl:template match="dss:SignatureAnalysis">
    	<div>
	    	<xsl:variable name="indicationText" select="dss:Conclusion/dss:Indication/text()"/>
	        <xsl:variable name="indicationCssClass">
	        	<xsl:choose>
					<xsl:when test="$indicationText='PASSED'">success</xsl:when>
					<xsl:when test="$indicationText='INDETERMINATE'">warning</xsl:when>
					<xsl:when test="$indicationText='FAILED'">danger</xsl:when>
					<xsl:otherwise>default</xsl:otherwise>
				</xsl:choose>
	        </xsl:variable>
    		<div>
    			<xsl:attribute name="class">panel panel-<xsl:value-of select="$indicationCssClass" /></xsl:attribute>
	    		<div>
	    			<xsl:attribute name="class">panel-heading</xsl:attribute>
		    		<xsl:attribute name="data-target">#collapseSigAnalysis<xsl:value-of select="@Id"/></xsl:attribute>
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
			        
			        <span>
						<xsl:attribute name="class">pull-right</xsl:attribute>
						<xsl:value-of select="@SignatureQualification"/>	       			
	       			</span>
			        
	    			Signature <xsl:value-of select="@Id"/>
		        </div>
	    		<div>
	    			<xsl:attribute name="class">panel-body collapse in</xsl:attribute>
		        	<xsl:attribute name="id">collapseSigAnalysis<xsl:value-of select="@Id"/></xsl:attribute>
		        	<xsl:apply-templates/>
	    		</div>
    		</div>
    	</div>
    </xsl:template>

    <xsl:template name="signature-conclusion">
        <xsl:param name="Conclusion"/>
        
        <xsl:variable name="indicationText" select="$Conclusion/dss:Indication"/>
        <xsl:variable name="indicationCssClass">
        	<xsl:choose>
				<xsl:when test="$indicationText='PASSED'">label-success</xsl:when>
				<xsl:when test="$indicationText='INDETERMINATE'">label-warning</xsl:when>
				<xsl:when test="$indicationText='FAILED'">label-danger</xsl:when>
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
    
    <xsl:template match="dss:FC|dss:ISC|dss:VCI|dss:CV|dss:SAV|dss:XCV|dss:PSV|dss:PCV|dss:VTS">
		<div>
			<xsl:attribute name="class">row</xsl:attribute>
			<xsl:attribute name="style">margin-bottom:5px;margin-top:5px;</xsl:attribute>
			<div>
				<xsl:attribute name="class">col-md-8</xsl:attribute>
				<strong>
					<xsl:choose>
						<xsl:when test="name(.) = 'FC'">
							Format Checking (FC)
						</xsl:when>
						<xsl:when test="name(.) = 'ISC'">
							Identification of the Signing Certificate (ISC)
						</xsl:when>
						<xsl:when test="name(.) = 'VCI'">
							Validation Context Initialization (VCI)
						</xsl:when>
						<xsl:when test="name(.) = 'CV'">
							Cryptographic Verification (CV)
						</xsl:when>
						<xsl:when test="name(.) = 'SAV'">
							Signature Acceptance Validation (SAV)
						</xsl:when>
						<xsl:when test="name(.) = 'XCV'">
							X509 Certificate Validation (XCV)
						</xsl:when>
						<xsl:when test="name(.) = 'PSV'">
							Past Signature Validation (PSV)
						</xsl:when>
						<xsl:when test="name(.) = 'PCV'">
							Past Certificate Validation (PCV)
						</xsl:when>
						<xsl:when test="name(.) = 'VTS'">
							Validation Time Sliding (VTS)
						</xsl:when>
						<xsl:otherwise>
							<xsl:value-of select="name(.)" />
						</xsl:otherwise>
					</xsl:choose>
					:
				</strong>
			</div>
			<div>
				<xsl:attribute name="class">col-md-4</xsl:attribute>
				<xsl:call-template name="signature-conclusion">
					<xsl:with-param name="Conclusion" select="dss:Conclusion" />
				</xsl:call-template>
			</div>
		</div>
		<xsl:apply-templates />
    </xsl:template>

	<xsl:template match="dss:SubXCV">
    	<div>
    		<xsl:variable name="indicationText" select="dss:Conclusion/dss:Indication/text()"/>
	        <xsl:variable name="indicationCssClass">
	        	<xsl:choose>
					<xsl:when test="$indicationText='PASSED'">success</xsl:when>
					<xsl:when test="$indicationText='INDETERMINATE'">warning</xsl:when>
					<xsl:when test="$indicationText='FAILED'">danger</xsl:when>
					<xsl:otherwise>default</xsl:otherwise>
				</xsl:choose>
	        </xsl:variable>
       		<xsl:attribute name="id"><xsl:value-of select="@Id"/></xsl:attribute>
    		<div>
    			<xsl:attribute name="class">panel panel-<xsl:value-of select="$indicationCssClass" /></xsl:attribute>
    			<xsl:attribute name="style">margin-top : 10px</xsl:attribute>
	    		<div>
	    			<xsl:attribute name="class">panel-heading</xsl:attribute>
		    		<xsl:attribute name="data-target">#collapseSubXCV<xsl:value-of select="@Id"/></xsl:attribute>
			       	<xsl:attribute name="data-toggle">collapse</xsl:attribute>
			       	
		       		<xsl:if test="@TrustAnchor = 'true'">
		       			<span>
							<xsl:attribute name="class">glyphicon glyphicon-thumbs-up pull-right</xsl:attribute>
							<xsl:attribute name="style">font-size : 20px;</xsl:attribute>
							<xsl:attribute name="title">Trust Anchor</xsl:attribute>		       			
		       			</span>
		       		</xsl:if>
			       	
	    			Certificate Id=<xsl:value-of select="@Id"/>
		        </div>
		        
		       	<xsl:if test="@TrustAnchor != 'true'">
		    		<div>
		    			<xsl:attribute name="class">panel-body collapse in</xsl:attribute>
			        	<xsl:attribute name="id">collapseSubXCV<xsl:value-of select="@Id"/></xsl:attribute>
			        	<xsl:apply-templates/>
		    		</div>
	    		</xsl:if>
    		</div>
    	</div>
    </xsl:template>
    
	<xsl:template match="dss:RFC">
    	<div>
    		<xsl:variable name="indicationText" select="dss:Conclusion/dss:Indication/text()"/>
	        <xsl:variable name="indicationCssClass">
	        	<xsl:choose>
					<xsl:when test="$indicationText='PASSED'">success</xsl:when>
					<xsl:when test="$indicationText='INDETERMINATE'">warning</xsl:when>
					<xsl:when test="$indicationText='FAILED'">danger</xsl:when>
					<xsl:otherwise>default</xsl:otherwise>
				</xsl:choose>
	        </xsl:variable>
       		<xsl:attribute name="id"><xsl:value-of select="@Id"/></xsl:attribute>
    		<div>
    			<xsl:attribute name="class">panel panel-<xsl:value-of select="$indicationCssClass" /></xsl:attribute>
    			<xsl:attribute name="style">margin-top : 10px</xsl:attribute>
	    		<div>
	    			<xsl:attribute name="class">panel-heading</xsl:attribute>
		    		<xsl:attribute name="data-target">#collapseRFC<xsl:value-of select="@Id"/></xsl:attribute>
			       	<xsl:attribute name="data-toggle">collapse</xsl:attribute>
	    			Revocation Freshness Checker (RFC)
		        </div>
	    		<div>
	    			<xsl:attribute name="class">panel-body collapse in</xsl:attribute>
		        	<xsl:attribute name="id">collapseRFC<xsl:value-of select="@Id"/></xsl:attribute>
		        	<xsl:apply-templates/>
	    		</div>
    		</div>
    	</div>
    </xsl:template>

    <xsl:template match="dss:Constraint">
	    <div>
	    	<xsl:attribute name="class">row</xsl:attribute>
	    	<div>
	    		<xsl:attribute name="class">col-md-8</xsl:attribute>
				<xsl:value-of select="dss:Name"/>
	    		<xsl:if test="@Id">
	    			<a> 
						<xsl:attribute name="href">#<xsl:value-of select="@Id"/></xsl:attribute>
						<xsl:attribute name="title">Details</xsl:attribute>
						<xsl:attribute name="style">margin-left : 10px</xsl:attribute>
						<span>
							<xsl:attribute name="class">glyphicon glyphicon-circle-arrow-right</xsl:attribute>
						</span>
					</a>
	    		</xsl:if>
	    	</div>
	    	<div>
	    		<xsl:attribute name="class">col-md-4</xsl:attribute>
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
					<xsl:when test="$statusText='INFORMATION'">
						<span>
							<xsl:attribute name="class">glyphicon glyphicon-info-sign text-info</xsl:attribute>
							<xsl:attribute name="title"><xsl:value-of select="dss:Info" /></xsl:attribute>
						</span>
					</xsl:when>
					<xsl:otherwise>
						<span>
							<xsl:value-of select="dss:Status" />
						</span>
					</xsl:otherwise>
	    		</xsl:choose>
	    		
	    		<xsl:if test="dss:AdditionalInfo">
		    		<span>
		    			<xsl:attribute name="class">glyphicon glyphicon-plus-sign text-info</xsl:attribute>
						<xsl:attribute name="style">margin-left : 10px</xsl:attribute>
						<xsl:attribute name="data-toggle">tooltip</xsl:attribute>
						<xsl:attribute name="data-placement">right</xsl:attribute>
						<xsl:attribute name="title"><xsl:value-of select="dss:AdditionalInfo" /></xsl:attribute>
		    		</span>
	    		</xsl:if>
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
