<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0" 
	xmlns:xsl="http://www.w3.org/1999/XSL/Transform" 
	xmlns:fo="http://www.w3.org/1999/XSL/Format"
	xmlns:fox="http://xmlgraphics.apache.org/fop/extensions"
	xmlns:dss="http://dss.esig.europa.eu/validation/simple-report">
	<xsl:output method="xml" indent="yes" />

	<xsl:param name="rootUrlInTlBrowser">https://eidas.ec.europa.eu/efda/tl-browser/#/screen</xsl:param>
	<xsl:param name="euTLSubDirectoryInTlBrowser">/tl</xsl:param>
	<xsl:param name="tcTLSubDirectoryInTlBrowser">/tc-tl</xsl:param>
	<xsl:param name="trustmarkSubDirectoryInTlBrowser">/trustmark</xsl:param>
	<xsl:param name="euGenericTSLType">http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric</xsl:param>

	<xsl:template match="/dss:SimpleReport">
		<fo:root>
			<xsl:attribute name="font-family">sans-serif</xsl:attribute>
			
			<fo:layout-master-set>
				<fo:simple-page-master>
					<xsl:attribute name="master-name">A4-portrait</xsl:attribute>
					<xsl:attribute name="page-height">29.7cm</xsl:attribute>
					<xsl:attribute name="page-width">21cm</xsl:attribute>
					<xsl:attribute name="margin-top">1cm</xsl:attribute>
					<xsl:attribute name="margin-bottom">1cm</xsl:attribute>
					<xsl:attribute name="margin-right">2.5cm</xsl:attribute>
					<xsl:attribute name="margin-left">2.5cm</xsl:attribute>
			
					<fo:region-body>
						<xsl:attribute name="margin-top">1cm</xsl:attribute>
						<xsl:attribute name="margin-bottom">1cm</xsl:attribute>
					</fo:region-body>

					<fo:region-after>
						<xsl:attribute name="region-name">page-footer</xsl:attribute>
						<xsl:attribute name="extent">0.5cm</xsl:attribute>
					</fo:region-after>
				</fo:simple-page-master>
			</fo:layout-master-set>

			<fo:bookmark-tree>
				<fo:bookmark>
					<xsl:attribute name="internal-destination">policy</xsl:attribute>
					<fo:bookmark-title>Validation Policy</fo:bookmark-title>
				</fo:bookmark>
				
				<xsl:for-each select="dss:Signature">
					<xsl:variable name="index"><xsl:value-of select="count(preceding-sibling::dss:Signature) + 1" /></xsl:variable>
					<fo:bookmark>
						<xsl:attribute name="internal-destination">signature-<xsl:value-of select="$index" /></xsl:attribute>
						<fo:bookmark-title>Signature <xsl:value-of select="$index" /></fo:bookmark-title>
					</fo:bookmark>
					<xsl:for-each select="dss:Timestamps/dss:Timestamp">
						<xsl:variable name="index_tst"><xsl:value-of select="count(preceding-sibling::dss:Timestamp) + 1" /></xsl:variable>
						<fo:bookmark>
							<xsl:attribute name="internal-destination">timestamp-<xsl:value-of select="$index" />-<xsl:value-of select="$index_tst" /></xsl:attribute>
							<fo:bookmark-title>Timestamp <xsl:value-of select="$index" />-<xsl:value-of select="$index_tst" /></fo:bookmark-title>
						</fo:bookmark>
					</xsl:for-each>
					<xsl:for-each select="dss:EvidenceRecords/dss:EvidenceRecord">
						<xsl:variable name="index_er"><xsl:value-of select="count(preceding-sibling::dss:EvidenceRecord) + 1" /></xsl:variable>
						<fo:bookmark>
							<xsl:attribute name="internal-destination">evidence-record-<xsl:value-of select="$index" />-<xsl:value-of select="$index_er" /></xsl:attribute>
							<fo:bookmark-title>Evidence Record <xsl:value-of select="$index" />-<xsl:value-of select="$index_er" /></fo:bookmark-title>
						</fo:bookmark>
						<xsl:for-each select="dss:Timestamps/dss:Timestamp">
							<xsl:variable name="index_er_tst"><xsl:value-of select="count(preceding-sibling::dss:Timestamp) + 1" /></xsl:variable>
							<fo:bookmark>
								<xsl:attribute name="internal-destination">timestamp-<xsl:value-of select="$index" />-<xsl:value-of select="$index_er" />-<xsl:value-of select="$index_er_tst" /></xsl:attribute>
								<fo:bookmark-title>Timestamp <xsl:value-of select="$index" />-<xsl:value-of select="$index_er" />-<xsl:value-of select="$index_er_tst" /></fo:bookmark-title>
							</fo:bookmark>
						</xsl:for-each>
					</xsl:for-each>
				</xsl:for-each>
				
				<xsl:for-each select="dss:Timestamp">
					<xsl:variable name="index"><xsl:value-of select="count(preceding-sibling::dss:Timestamp) + 1" /></xsl:variable>
					<fo:bookmark>
						<xsl:attribute name="internal-destination">timestamp-<xsl:value-of select="$index" /></xsl:attribute>
						<fo:bookmark-title>Timestamp <xsl:value-of select="$index" /></fo:bookmark-title>
					</fo:bookmark>
				</xsl:for-each>

				<xsl:for-each select="dss:EvidenceRecord">
					<xsl:variable name="index"><xsl:value-of select="count(preceding-sibling::dss:EvidenceRecord) + 1" /></xsl:variable>
					<fo:bookmark>
						<xsl:attribute name="internal-destination">evidence-record-<xsl:value-of select="$index" /></xsl:attribute>
						<fo:bookmark-title>Evidence Record <xsl:value-of select="$index" /></fo:bookmark-title>
					</fo:bookmark>
					<xsl:for-each select="dss:Timestamps/dss:Timestamp">
						<xsl:variable name="index_tst"><xsl:value-of select="count(preceding-sibling::dss:Timestamp) + 1" /></xsl:variable>
						<fo:bookmark>
							<xsl:attribute name="internal-destination">timestamp-<xsl:value-of select="$index" />-<xsl:value-of select="$index_tst" /></xsl:attribute>
							<fo:bookmark-title>Timestamp <xsl:value-of select="$index" />-<xsl:value-of select="$index_tst" /></fo:bookmark-title>
						</fo:bookmark>
					</xsl:for-each>
				</xsl:for-each>
				
				<fo:bookmark>
					<xsl:attribute name="internal-destination">docInfo</xsl:attribute>
					<fo:bookmark-title>Document Information</fo:bookmark-title>
				</fo:bookmark>
			</fo:bookmark-tree>

			<fo:page-sequence>
				<xsl:attribute name="master-reference">A4-portrait</xsl:attribute>
	
				<fo:static-content>
					<xsl:attribute name="flow-name">page-footer</xsl:attribute>
					<xsl:attribute name="font-size">5pt</xsl:attribute>
					
					<fo:block>
						<xsl:attribute name="color">grey</xsl:attribute>
						<xsl:attribute name="border-top-style">solid</xsl:attribute>
						<xsl:attribute name="border-top-color">grey</xsl:attribute>
						<xsl:attribute name="text-align-last">justify</xsl:attribute>
						<xsl:attribute name="padding-top">3px</xsl:attribute>
					
						<fo:inline>
							 <fo:basic-link>
							 	<xsl:attribute name="external-destination">url('https://github.com/esig/dss')</xsl:attribute>
							 	Generated by DSS v.${project.version}
							 </fo:basic-link>
							 <xsl:text>with validation time </xsl:text><xsl:value-of select="@ValidationTime" />
						</fo:inline>
						
						<fo:leader/>

						<fo:inline>
							<fo:page-number />
							/
							<fo:page-number-citation>
								<xsl:attribute name="ref-id">theEnd</xsl:attribute>
							</fo:page-number-citation> 
						</fo:inline>
					</fo:block>
				</fo:static-content>

				<fo:flow>
					<xsl:attribute name="flow-name">xsl-region-body</xsl:attribute>
					<xsl:attribute name="font-size">8pt</xsl:attribute>
					
					<xsl:apply-templates select="dss:ValidationPolicy"/>
					<xsl:apply-templates select="dss:Signature"/>
					<xsl:apply-templates select="dss:Timestamp"/>
					<xsl:apply-templates select="dss:EvidenceRecord"/>
					
	    			<xsl:call-template name="documentInformation"/>
	    			
   					<xsl:if test="dss:Semantic">
   						
						<fo:block>
							<xsl:attribute name="keep-together.within-page">always</xsl:attribute>
							<xsl:attribute name="font-weight">bold</xsl:attribute>
							<xsl:attribute name="margin-top">5px</xsl:attribute>
				       		<xsl:attribute name="margin-bottom">2px</xsl:attribute>
				       		<xsl:attribute name="color">#004494</xsl:attribute>
				       		
				       		<xsl:attribute name="border-bottom-style">solid</xsl:attribute>
				       		<xsl:attribute name="border-color">#004494</xsl:attribute>
				       		<xsl:attribute name="border-width">1px</xsl:attribute>
   					
   							Semantics
   						</fo:block>

						<fo:block-container>
							<xsl:attribute name="margin-top">2px</xsl:attribute>
							<xsl:attribute name="margin-bottom">2px</xsl:attribute>

							<xsl:apply-templates select="dss:Semantic"/>
						</fo:block-container>
   					</xsl:if>
	    			
					<fo:block>
						<xsl:attribute name="id">theEnd</xsl:attribute>
					</fo:block>
				</fo:flow>
				
			</fo:page-sequence>

		</fo:root>
		
	</xsl:template>
	
    <xsl:template match="dss:ValidationPolicy">
    
		<fo:block-container>
			<xsl:attribute name="margin-top">4px</xsl:attribute>
			<fo:block-container>
				<xsl:attribute name="margin">0</xsl:attribute>
				
				<fo:block>
					<xsl:attribute name="keep-with-next">always</xsl:attribute>
					<xsl:attribute name="font-weight">bold</xsl:attribute>
		       		
		       		<xsl:attribute name="border-bottom-style">solid</xsl:attribute>
		       		<xsl:attribute name="border-color">#004494</xsl:attribute>
		       		<xsl:attribute name="border-width">1px</xsl:attribute>
		       		
					<xsl:attribute name="margin-bottom">2px</xsl:attribute>
		       		
					<xsl:attribute name="id">policy</xsl:attribute>
					<xsl:text>Validation Policy: <xsl:value-of select="dss:PolicyName"/></xsl:text>
		    	</fo:block>
	    	</fo:block-container>
		</fo:block-container>
		
		<fo:block-container>
       		<xsl:attribute name="border-left-style">solid</xsl:attribute>
       		<xsl:attribute name="border-color">#004494</xsl:attribute>
       		<xsl:attribute name="border-width">1px</xsl:attribute>
       		
			<xsl:attribute name="margin-top">7px</xsl:attribute>
			<xsl:attribute name="margin-bottom">5px</xsl:attribute>
       		
			<fo:block-container>
				<xsl:attribute name="margin-left">10px</xsl:attribute>
				
				<fo:block-container>
					<xsl:attribute name="margin">0</xsl:attribute>
				
					<fo:block>
						<xsl:attribute name="margin-top">5px</xsl:attribute>
						<xsl:attribute name="margin-bottom">5px</xsl:attribute>
						<xsl:attribute name="font-size">7pt</xsl:attribute>
											
       					<xsl:value-of select="dss:PolicyDescription"/>
			       	</fo:block>
		       	</fo:block-container>
	       	</fo:block-container>
	       	
    	</fo:block-container>
		
    </xsl:template>
    
    <xsl:template match="dss:Signature|dss:Timestamp|dss:EvidenceRecord">
        <xsl:variable name="nodeName" select="name()" />
        
		<xsl:param name="sigCounter" />
		<xsl:param name="erCounter" />
    	<xsl:variable name="counter">
    		<xsl:if test="$nodeName = 'Signature'">
    			<xsl:value-of select="count(preceding-sibling::dss:Signature) + 1" />
    		</xsl:if>
    		<xsl:if test="$nodeName = 'Timestamp'">
    			<xsl:value-of select="count(preceding-sibling::dss:Timestamp) + 1" />
    		</xsl:if>
			<xsl:if test="$nodeName = 'EvidenceRecord'">
				<xsl:value-of select="count(preceding-sibling::dss:EvidenceRecord) + 1" />
			</xsl:if>
    	</xsl:variable>
    
        <xsl:variable name="indicationText" select="dss:Indication/text()"/>
        <xsl:variable name="idToken" select="@Id" />
        <xsl:variable name="indicationColor">
        	<xsl:choose>
				<xsl:when test="$indicationText='TOTAL_PASSED'">green</xsl:when>
				<xsl:when test="$indicationText='PASSED'">green</xsl:when>
				<xsl:when test="$indicationText='INDETERMINATE'">orange</xsl:when>
				<xsl:when test="$indicationText='FAILED'">red</xsl:when>
				<xsl:when test="$indicationText='TOTAL_FAILED'">red</xsl:when>
			</xsl:choose>
        </xsl:variable>
        
        <fo:table table-layout="fixed">
    		<xsl:if test="$nodeName = 'Signature'">
    			<xsl:attribute name="id">signature-<xsl:value-of select="$counter" /></xsl:attribute>
    		</xsl:if>
    		<xsl:if test="$nodeName = 'Timestamp'">
				<xsl:variable name="tstCounter">
					<xsl:if test="$sigCounter"><xsl:value-of select="$sigCounter" />-</xsl:if><xsl:if test="$erCounter"><xsl:value-of select="$erCounter" />-</xsl:if><xsl:value-of select="$counter" />
				</xsl:variable>
    			<xsl:attribute name="id">timestamp-<xsl:value-of select="$tstCounter" /></xsl:attribute>
    		</xsl:if>
			<xsl:if test="$nodeName = 'EvidenceRecord'">
				<xsl:variable name="currentERCounter">
					<xsl:if test="$sigCounter"><xsl:value-of select="$sigCounter" />-</xsl:if><xsl:value-of select="$counter" />
				</xsl:variable>
				<xsl:attribute name="id">evidence-record-<xsl:value-of select="$currentERCounter" /></xsl:attribute>
			</xsl:if>
			
			<xsl:attribute name="margin-top">7px</xsl:attribute>
			<xsl:attribute name="margin-bottom">5px</xsl:attribute>
			
			<fo:table-body>
				<xsl:attribute name="start-indent">0</xsl:attribute>
				<xsl:attribute name="end-indent">0</xsl:attribute>
				
		    	<fo:table-row>
		    	
					<xsl:attribute name="font-weight">bold</xsl:attribute>
		       		
		       		<xsl:attribute name="border-bottom-style">solid</xsl:attribute>
		       		<xsl:attribute name="border-color">#004494</xsl:attribute>
		       		<xsl:attribute name="border-width">1px</xsl:attribute>
		       		
					<xsl:attribute name="margin-bottom">2px</xsl:attribute>
		       		
					<fo:table-cell>
						<fo:block>
		    				<xsl:attribute name="font-weight">bold</xsl:attribute>

							<xsl:if test="$nodeName = 'Signature'">
								<xsl:text>Signature: </xsl:text>
							</xsl:if>
							<xsl:if test="$nodeName = 'Timestamp'">
								<xsl:text>Timestamp: </xsl:text>
							</xsl:if>
							<xsl:if test="$nodeName = 'EvidenceRecord'">
								<xsl:text>Evidence Record: </xsl:text>
							</xsl:if>
				       		<xsl:value-of select="$idToken" />
			       		</fo:block>
					</fo:table-cell>
				</fo:table-row>

			</fo:table-body>
		</fo:table>
		
		
		<fo:block-container>
       		<xsl:attribute name="border-left-style">solid</xsl:attribute>
       		<xsl:attribute name="border-color">#004494</xsl:attribute>
       		<xsl:attribute name="border-width">1px</xsl:attribute>
       		
			<xsl:attribute name="margin-top">5px</xsl:attribute>
			<xsl:attribute name="margin-bottom">5px</xsl:attribute>
       		
			<fo:block-container>
				<xsl:attribute name="margin-left">10px</xsl:attribute>
				<fo:block-container>
					<xsl:attribute name="margin">0</xsl:attribute>
				
					<fo:table table-layout="fixed">
						<xsl:attribute name="font-size">7pt</xsl:attribute>
						
						<fo:table-column>
							<xsl:attribute name="column-width">25%</xsl:attribute>
						</fo:table-column>
						<fo:table-column>
							<xsl:attribute name="column-width">75%</xsl:attribute>
						</fo:table-column>
						<fo:table-body>
						
							<xsl:if test="dss:Filename">
								<fo:table-row>
									<xsl:attribute name="margin-top">1px</xsl:attribute>
									<xsl:attribute name="margin-bottom">1px</xsl:attribute>
									<fo:table-cell>
										<fo:block>
											<xsl:attribute name="margin-top">1px</xsl:attribute>
											<xsl:attribute name="margin-bottom">1px</xsl:attribute>
											
											<xsl:attribute name="font-weight">bold</xsl:attribute>
											<xsl:if test="$nodeName = 'Signature'">
								            	Signature filename:
											</xsl:if>
											<xsl:if test="$nodeName = 'Timestamp'">
								            	Timestamp filename:
											</xsl:if>
											<xsl:if test="$nodeName = 'EvidenceRecord'">
												Evidence Record filename:
											</xsl:if>
										</fo:block>
									</fo:table-cell>
									<fo:table-cell>
										<fo:block>
											<xsl:attribute name="margin-top">1px</xsl:attribute>
											<xsl:attribute name="margin-bottom">1px</xsl:attribute>
											
											<xsl:value-of select="dss:Filename" />
										</fo:block>
									</fo:table-cell>
								</fo:table-row>
							</xsl:if>
						
							<xsl:if test="dss:SignatureLevel | dss:TimestampLevel">
								<fo:table-row>
									<xsl:attribute name="margin-top">1px</xsl:attribute>
									<xsl:attribute name="margin-bottom">1px</xsl:attribute>
									<fo:table-cell>
										<fo:block>
											<xsl:attribute name="margin-top">1px</xsl:attribute>
											<xsl:attribute name="margin-bottom">1px</xsl:attribute>
											
				       						<xsl:attribute name="font-weight">bold</xsl:attribute>
											Qualification level:
										</fo:block>
									</fo:table-cell>
									<fo:table-cell>
										<fo:block>
											<xsl:attribute name="margin-top">1px</xsl:attribute>
											<xsl:attribute name="margin-bottom">1px</xsl:attribute>
											
											<xsl:if test="dss:SignatureLevel">
												<xsl:value-of select="dss:SignatureLevel" />
											</xsl:if>
											<xsl:if test="dss:TimestampLevel">
												<xsl:value-of select="dss:TimestampLevel/@description" />
											</xsl:if>
										</fo:block>
									</fo:table-cell>
								</fo:table-row>
							</xsl:if>

							<xsl:apply-templates select="dss:QualificationDetails" />
						
							<fo:table-row>
								<xsl:attribute name="margin-top">1px</xsl:attribute>
								<xsl:attribute name="margin-bottom">1px</xsl:attribute>
								<fo:table-cell>
									<fo:block>
										<xsl:attribute name="margin-top">1px</xsl:attribute>
										<xsl:attribute name="margin-bottom">1px</xsl:attribute>
										
			       						<xsl:attribute name="font-weight">bold</xsl:attribute>
										Indication:
									</fo:block>
								</fo:table-cell>
								<fo:table-cell>
									<fo:block>
										<xsl:attribute name="margin-top">1px</xsl:attribute>
										<xsl:attribute name="margin-bottom">1px</xsl:attribute>
											
				       					<xsl:attribute name="font-weight">bold</xsl:attribute>
				       					<xsl:attribute name="color"><xsl:value-of select="$indicationColor" /></xsl:attribute>
				       					<xsl:variable name="subIndication"><xsl:value-of select="dss:SubIndication" /></xsl:variable>
										<xsl:value-of select="dss:Indication" /><xsl:if test="$subIndication != ''"> - <xsl:value-of select="dss:SubIndication" /></xsl:if>
									</fo:block>
								</fo:table-cell>
							</fo:table-row>

							<xsl:apply-templates select="dss:AdESValidationDetails" />
							
							<xsl:if test="@SignatureFormat">
								<fo:table-row>
									<xsl:attribute name="margin-top">1px</xsl:attribute>
									<xsl:attribute name="margin-bottom">1px</xsl:attribute>
									<fo:table-cell>
										<fo:block>
											<xsl:attribute name="margin-top">1px</xsl:attribute>
											<xsl:attribute name="margin-bottom">1px</xsl:attribute>
											
				       						<xsl:attribute name="font-weight">bold</xsl:attribute>
											Signature Format:
										</fo:block>
									</fo:table-cell>
									<fo:table-cell>
										<fo:block>
											<xsl:attribute name="margin-top">1px</xsl:attribute>
											<xsl:attribute name="margin-bottom">1px</xsl:attribute>
											
											<xsl:value-of select="@SignatureFormat" />
										</fo:block>
									</fo:table-cell>
								</fo:table-row>
							</xsl:if>

							<xsl:if test="dss:CertificateChain">
								<fo:table-row>
									<xsl:attribute name="margin-top">1px</xsl:attribute>
									<xsl:attribute name="margin-bottom">1px</xsl:attribute>
									<xsl:attribute name="page-break-inside">avoid</xsl:attribute>

									<fo:table-cell>
										<fo:block>
											<xsl:attribute name="margin-top">1px</xsl:attribute>
											<xsl:attribute name="margin-bottom">1px</xsl:attribute>

											<xsl:attribute name="font-weight">bold</xsl:attribute>
											Certificate chain:
										</fo:block>
									</fo:table-cell>
									<fo:table-cell>
										<xsl:choose>
											<xsl:when test="dss:CertificateChain/dss:Certificate">
												<xsl:for-each select="dss:CertificateChain/dss:Certificate">
													<xsl:variable name="index" select="position()"/>

													<fo:block>
														<fo:inline>
															<xsl:attribute name="margin-top">1px</xsl:attribute>
															<xsl:attribute name="margin-bottom">1px</xsl:attribute>
															<xsl:if test="$index = 1">
																<xsl:attribute name="font-weight">bold</xsl:attribute>
															</xsl:if>
															<xsl:if test="not(@trusted = 'true' or following-sibling::dss:Certificate[@trusted = 'true'])">
																<xsl:attribute name="color">gray</xsl:attribute>
															</xsl:if>
															<xsl:value-of select="dss:QualifiedName" />
														</fo:inline>
														<fo:inline>
															<xsl:if test="@trusted = 'true' and not(dss:TrustAnchors)"> (Trust anchor)</xsl:if>
															<xsl:apply-templates select="dss:TrustAnchors"/>
														</fo:inline>
													</fo:block>

												</xsl:for-each>
											</xsl:when>
											<xsl:otherwise>
												<fo:block>/</fo:block>
											</xsl:otherwise>
										</xsl:choose>
									</fo:table-cell>
								</fo:table-row>
							</xsl:if>
							
							<fo:table-row>
								<xsl:attribute name="margin-top">1px</xsl:attribute>
								<xsl:attribute name="margin-bottom">1px</xsl:attribute>
								<fo:table-cell>
									<fo:block>
										<xsl:attribute name="margin-top">1px</xsl:attribute>
										<xsl:attribute name="margin-bottom">1px</xsl:attribute>
											
			       						<xsl:attribute name="font-weight">bold</xsl:attribute>
										<xsl:if test="$nodeName = 'Signature'">
											On claimed time:
										</xsl:if>
										<xsl:if test="$nodeName = 'Timestamp'">
											Production time:
										</xsl:if>
										<xsl:if test="$nodeName = 'EvidenceRecord'">
											POE time:
										</xsl:if>
									</fo:block>
								</fo:table-cell>
								<fo:table-cell>
									<fo:block>
										<xsl:attribute name="margin-top">1px</xsl:attribute>
										<xsl:attribute name="margin-bottom">1px</xsl:attribute>
											
										<xsl:if test="$nodeName = 'Signature'">
											<xsl:call-template name="formatdate">
												<xsl:with-param name="DateTimeStr" select="dss:SigningTime"/>
											</xsl:call-template>
										</xsl:if>
										<xsl:if test="$nodeName = 'Timestamp'">
											<xsl:call-template name="formatdate">
												<xsl:with-param name="DateTimeStr" select="dss:ProductionTime"/>
											</xsl:call-template>
										</xsl:if>
										<xsl:if test="$nodeName = 'EvidenceRecord'">
											<xsl:call-template name="formatdate">
												<xsl:with-param name="DateTimeStr" select="dss:POETime"/>
											</xsl:call-template>
										</xsl:if>
									</fo:block>
								</fo:table-cell>
							</fo:table-row>
							
							<xsl:if test="dss:BestSignatureTime">
								<fo:table-row>
									<xsl:attribute name="margin-top">1px</xsl:attribute>
									<xsl:attribute name="margin-bottom">1px</xsl:attribute>
									<fo:table-cell>
										<fo:block>
											<xsl:attribute name="margin-top">1px</xsl:attribute>
											<xsl:attribute name="margin-bottom">1px</xsl:attribute>
											
				       						<xsl:attribute name="font-weight">bold</xsl:attribute>
											Best signature time:
										</fo:block>
									</fo:table-cell>
									<fo:table-cell>
										<fo:block>
											<xsl:attribute name="margin-top">1px</xsl:attribute>
											<xsl:attribute name="margin-bottom">1px</xsl:attribute>

											<xsl:call-template name="formatdate">
												<xsl:with-param name="DateTimeStr" select="dss:BestSignatureTime"/>
											</xsl:call-template>
										</fo:block>
									</fo:table-cell>
								</fo:table-row>
							</xsl:if>
							
							<xsl:if test="$nodeName = 'Signature'">
								<fo:table-row>
									<xsl:attribute name="margin-top">1px</xsl:attribute>
									<xsl:attribute name="margin-bottom">1px</xsl:attribute>
									<fo:table-cell>
										<fo:block>
											<xsl:attribute name="margin-top">1px</xsl:attribute>
											<xsl:attribute name="margin-bottom">1px</xsl:attribute>
											
				       						<xsl:attribute name="font-weight">bold</xsl:attribute>
											Signature position:
										</fo:block>
									</fo:table-cell>
									<fo:table-cell>
										<fo:block>
											<xsl:attribute name="margin-top">1px</xsl:attribute>
											<xsl:attribute name="margin-bottom">1px</xsl:attribute>
											
											<xsl:value-of select="$counter" /> out of <xsl:value-of select="count(ancestor::*/dss:Signature)"/>
										</fo:block>
									</fo:table-cell>
								</fo:table-row>
							</xsl:if>

							<xsl:apply-templates select="dss:SignatureScope" />
							<xsl:apply-templates select="dss:TimestampScope" />
							<xsl:apply-templates select="dss:EvidenceRecordScope" />
							
						</fo:table-body>	
					</fo:table>

					<xsl:variable name="sigPosition">
						<xsl:choose>
							<xsl:when test="$sigCounter"><xsl:value-of select="$sigCounter" /></xsl:when>
							<xsl:when test="$nodeName = 'Signature'"><xsl:value-of select="$counter" /></xsl:when>
						</xsl:choose>
					</xsl:variable>
					<xsl:variable name="erPosition">
						<xsl:choose>
							<xsl:when test="$nodeName = 'EvidenceRecord'"><xsl:value-of select="$counter" /></xsl:when>
						</xsl:choose>
					</xsl:variable>
		
					<xsl:apply-templates select="dss:Timestamps">
						<xsl:with-param name="sigCounter" select="$sigPosition"/>
						<xsl:with-param name="erCounter" select="$erPosition"/>
					</xsl:apply-templates>

					<xsl:apply-templates select="dss:EvidenceRecords">
						<xsl:with-param name="sigCounter" select="$counter"/>
					</xsl:apply-templates>
		
		       	</fo:block-container>
	       	</fo:block-container>
	       	
    	</fo:block-container>

    </xsl:template>

	<xsl:template match="dss:SignatureScope|dss:TimestampScope|dss:EvidenceRecordScope">
		<xsl:variable name="header">
			<xsl:choose>
				<xsl:when test="name() = 'SignatureScope'">Signature scope</xsl:when>
				<xsl:when test="name() = 'TimestampScope'">Timestamp scope</xsl:when>
				<xsl:when test="name() = 'EvidenceRecordScope'">Evidence Record scope</xsl:when>
			</xsl:choose>
		</xsl:variable>
		<fo:table-row>
			<xsl:attribute name="margin-top">1px</xsl:attribute>
			<xsl:attribute name="margin-bottom">1px</xsl:attribute>
			<xsl:attribute name="page-break-inside">avoid</xsl:attribute>

			<fo:table-cell>
				<fo:block>
					<xsl:attribute name="margin-top">1px</xsl:attribute>
					<xsl:attribute name="margin-bottom">1px</xsl:attribute>

					<xsl:attribute name="font-weight">bold</xsl:attribute>
					<xsl:value-of select="$header" />:
				</fo:block>
			</fo:table-cell>
			<fo:table-cell>
				<fo:block>
					<xsl:attribute name="margin-top">1px</xsl:attribute>
					<xsl:attribute name="margin-bottom">1px</xsl:attribute>

					<xsl:value-of select="@name" />	(<xsl:value-of select="@scope" />)
				</fo:block>
				<fo:block>
					<xsl:attribute name="margin-top">1px</xsl:attribute>
					<xsl:attribute name="margin-bottom">1px</xsl:attribute>

					<xsl:value-of select="." />
				</fo:block>
			</fo:table-cell>
		</fo:table-row>
	</xsl:template>

	<xsl:template match="dss:TrustAnchors">
		<xsl:apply-templates select="dss:TrustAnchor"/>
	</xsl:template>

	<xsl:template match="dss:TrustAnchor">
		<xsl:variable name="subDirectory">
			<xsl:choose>
				<xsl:when test="dss:TSLType and $euGenericTSLType = dss:TSLType"><xsl:value-of select="$euTLSubDirectoryInTlBrowser" /></xsl:when>
				<xsl:otherwise><xsl:value-of select="$tcTLSubDirectoryInTlBrowser" /></xsl:otherwise>
			</xsl:choose>
		</xsl:variable>
		<xsl:variable name="countryTlUrl" select="concat($rootUrlInTlBrowser, $subDirectory, '/', @countryCode)" />
		<xsl:variable name="countryTspUrl" select="concat($rootUrlInTlBrowser, $subDirectory,
				$trustmarkSubDirectoryInTlBrowser, '/', @countryCode, '/', dss:TrustServiceProviderRegistrationId)" />

		<xsl:text> </xsl:text>
		<fo:instream-foreign-object fox:alt-text="arrow-right" content-height="6px" content-width="6px" height="6px" width="6px">
			<svg viewBox="0 0 1792 1792" xmlns="http://www.w3.org/2000/svg"><path style="fill:black" d="M1413 896q0-27-18-45l-91-91-362-362q-18-18-45-18t-45 18l-91 91q-18 18-18 45t18 45l189 189h-502q-26 0-45 19t-19 45v128q0 26 19 45t45 19h502l-189 189q-19 19-19 45t19 45l91 91q18 18 45 18t45-18l362-362 91-91q18-18 18-45zm251 0q0 209-103 385.5t-279.5 279.5-385.5 103-385.5-103-279.5-279.5-103-385.5 103-385.5 279.5-279.5 385.5-103 385.5 103 279.5 279.5 103 385.5z"/></svg>
		</fo:instream-foreign-object>
		<xsl:text> </xsl:text>
		<fo:basic-link>
			<xsl:attribute name="external-destination"><xsl:value-of select="$countryTlUrl"/></xsl:attribute>
			<xsl:value-of select="@countryCode" />
		</fo:basic-link>
		<xsl:text> </xsl:text>
		<fo:instream-foreign-object fox:alt-text="arrow-right" content-height="6px" content-width="6px" height="6px" width="6px">
			<svg viewBox="0 0 1792 1792" xmlns="http://www.w3.org/2000/svg"><path style="fill:black" d="M1413 896q0-27-18-45l-91-91-362-362q-18-18-45-18t-45 18l-91 91q-18 18-18 45t18 45l189 189h-502q-26 0-45 19t-19 45v128q0 26 19 45t45 19h502l-189 189q-19 19-19 45t19 45l91 91q18 18 45 18t45-18l362-362 91-91q18-18 18-45zm251 0q0 209-103 385.5t-279.5 279.5-385.5 103-385.5-103-279.5-279.5-103-385.5 103-385.5 279.5-279.5 385.5-103 385.5 103 279.5 279.5 103 385.5z"/></svg>
		</fo:instream-foreign-object>
		<xsl:text> </xsl:text>
		<fo:basic-link>
			<xsl:attribute name="external-destination"><xsl:value-of select="$countryTspUrl"/></xsl:attribute>
			<xsl:value-of select="dss:TrustServiceProvider" />
		</fo:basic-link>
		<xsl:text> </xsl:text>

		<!-- optionally display TrustServices names -->
		<!--
		<fo:instream-foreign-object fox:alt-text="arrow-right" content-height="6px" content-width="6px" height="6px" width="6px">
			<svg viewBox="0 0 1792 1792" xmlns="http://www.w3.org/2000/svg"><path style="fill:black" d="M1413 896q0-27-18-45l-91-91-362-362q-18-18-45-18t-45 18l-91 91q-18 18-18 45t18 45l189 189h-502q-26 0-45 19t-19 45v128q0 26 19 45t45 19h502l-189 189q-19 19-19 45t19 45l91 91q18 18 45 18t45-18l362-362 91-91q18-18 18-45zm251 0q0 209-103 385.5t-279.5 279.5-385.5 103-385.5-103-279.5-279.5-103-385.5 103-385.5 279.5-279.5 385.5-103 385.5 103 279.5 279.5 103 385.5z"/></svg>
		</fo:instream-foreign-object>
		<xsl:text> </xsl:text>
		<xsl:for-each select="dss:TrustServiceName">
			<xsl:value-of select="." />
			<xsl:if test="position() &lt; last()">
				<xsl:text>; </xsl:text>
			</xsl:if>
		</xsl:for-each>
		-->

	</xsl:template>

	<xsl:template match="dss:QualificationDetails|dss:AdESValidationDetails">
		<xsl:variable name="header">
			<xsl:choose>
				<xsl:when test="name() = 'AdESValidationDetails'">AdES Validation Details</xsl:when>
				<xsl:when test="name() = 'QualificationDetails'">Qualification Details</xsl:when>
			</xsl:choose>
		</xsl:variable>
		<fo:table-row>
			<xsl:attribute name="margin-top">1px</xsl:attribute>
			<xsl:attribute name="margin-bottom">1px</xsl:attribute>
			<fo:table-cell>
				<fo:block>
					<xsl:attribute name="margin-top">1px</xsl:attribute>
					<xsl:attribute name="margin-bottom">1px</xsl:attribute>

					<xsl:attribute name="font-weight">bold</xsl:attribute>
					<xsl:value-of select="$header" />:
				</fo:block>
			</fo:table-cell>
			<fo:table-cell>

				<xsl:apply-templates select="dss:Error" />
				<xsl:apply-templates select="dss:Warning" />
				<xsl:apply-templates select="dss:Info" />

			</fo:table-cell>
		</fo:table-row>
	</xsl:template>

	<xsl:template match="dss:Error|dss:Warning|dss:Info">
		<xsl:variable name="indicationColor">
        	<xsl:choose>
				<xsl:when test="name() = 'Error'">red</xsl:when>
				<xsl:when test="name() = 'Warning'">orange</xsl:when>
				<xsl:otherwise>black</xsl:otherwise>
			</xsl:choose>
        </xsl:variable>
	    <fo:block>
			<xsl:attribute name="margin-top">1px</xsl:attribute>
			<xsl:attribute name="margin-bottom">1px</xsl:attribute>
											
			<xsl:attribute name="color"><xsl:value-of select="$indicationColor" /></xsl:attribute>
			<xsl:value-of select="." />
		</fo:block>
	</xsl:template>

	<xsl:template match="dss:Timestamps">
		<xsl:param name="sigCounter" />
		<xsl:param name="erCounter" />
		<fo:block-container>
			<fo:block>
				<xsl:attribute name="margin-top">2px</xsl:attribute>
				<xsl:attribute name="margin-bottom">2px</xsl:attribute>
				<xsl:attribute name="font-size">7pt</xsl:attribute>

				<xsl:attribute name="font-weight">bold</xsl:attribute>
				Timestamps:
			</fo:block>
		</fo:block-container>
		<fo:block-container>
			<fo:block>
				<xsl:apply-templates>
					<xsl:with-param name="sigCounter" select="$sigCounter"/>
					<xsl:with-param name="erCounter" select="$erCounter"/>
				</xsl:apply-templates>
			</fo:block>
		</fo:block-container>
	</xsl:template>

	<xsl:template match="dss:EvidenceRecords">
		<xsl:param name="sigCounter" />
		<fo:block-container>
			<fo:block>
				<xsl:attribute name="margin-top">2px</xsl:attribute>
				<xsl:attribute name="margin-bottom">2px</xsl:attribute>
				<xsl:attribute name="font-size">7pt</xsl:attribute>

				<xsl:attribute name="font-weight">bold</xsl:attribute>
				Evidence records:
			</fo:block>
		</fo:block-container>
		<fo:block-container>
			<fo:block>
				<xsl:apply-templates>
					<xsl:with-param name="sigCounter" select="$sigCounter"/>
				</xsl:apply-templates>
			</fo:block>
		</fo:block-container>
	</xsl:template>
    
    <xsl:template name="documentInformation">
    	<fo:table table-layout="fixed">
			<xsl:attribute name="margin-top">5px</xsl:attribute>
			
			<fo:table-body>
				<xsl:attribute name="start-indent">0</xsl:attribute>
				<xsl:attribute name="end-indent">0</xsl:attribute>
				
				<fo:table-row>
					<fo:table-cell>
						<fo:block>
							<xsl:attribute name="keep-with-next">always</xsl:attribute>
							<xsl:attribute name="font-weight">bold</xsl:attribute>
				       		
				       		<xsl:attribute name="border-bottom-style">solid</xsl:attribute>
				       		<xsl:attribute name="border-color">#004494</xsl:attribute>
				       		<xsl:attribute name="border-width">1px</xsl:attribute>
				       		
							<xsl:attribute name="margin-bottom">2px</xsl:attribute>
				       		
    						<xsl:attribute name="id">docInfo</xsl:attribute>
    						<xsl:text>Document Information</xsl:text>
				    	</fo:block>
	    			</fo:table-cell>
				</fo:table-row>
			</fo:table-body>
		</fo:table>
		
    	<fo:block-container>
       		<xsl:attribute name="border-left-style">solid</xsl:attribute>
       		<xsl:attribute name="border-color">#004494</xsl:attribute>
       		<xsl:attribute name="border-width">1px</xsl:attribute>
       		
			<xsl:attribute name="margin-top">2px</xsl:attribute>
			<xsl:attribute name="margin-bottom">2px</xsl:attribute>
			<xsl:attribute name="font-size">7pt</xsl:attribute>
       		
			<fo:block-container>
				<xsl:attribute name="margin-left">10px</xsl:attribute>
				<fo:block-container>
					<xsl:attribute name="margin">0</xsl:attribute>
					
					<fo:table table-layout="fixed">
						<xsl:attribute name="font-size">7pt</xsl:attribute>
						
						<xsl:attribute name="page-break-inside">avoid</xsl:attribute>
						<fo:table-column>
							<xsl:attribute name="column-width">25%</xsl:attribute>
						</fo:table-column>
						<fo:table-column>
							<xsl:attribute name="column-width">75%</xsl:attribute>
						</fo:table-column>
						<fo:table-body>

							<xsl:apply-templates select="dss:ContainerType"/>
							<xsl:apply-templates select="dss:PDFAInfo"/>
						
							<fo:table-row>
								<xsl:attribute name="margin-top">1px</xsl:attribute>
								<xsl:attribute name="margin-bottom">1px</xsl:attribute>
								<fo:table-cell>
									<fo:block>
										<xsl:attribute name="margin-top">1px</xsl:attribute>
										<xsl:attribute name="margin-bottom">1px</xsl:attribute>
											
			       						<xsl:attribute name="font-weight">bold</xsl:attribute>
										Signatures status:
									</fo:block>
								</fo:table-cell>
								<fo:table-cell>
									<fo:block>
										<xsl:attribute name="margin-top">1px</xsl:attribute>
										<xsl:attribute name="margin-bottom">1px</xsl:attribute>
											
				       					<xsl:value-of select="dss:ValidSignaturesCount"/> valid signatures, out of <xsl:value-of select="dss:SignaturesCount"/>
									</fo:block>
								</fo:table-cell>
							</fo:table-row>
							<fo:table-row>
								<xsl:attribute name="margin-top">1px</xsl:attribute>
								<xsl:attribute name="margin-bottom">1px</xsl:attribute>
								<fo:table-cell>
									<fo:block>
										<xsl:attribute name="margin-top">1px</xsl:attribute>
										<xsl:attribute name="margin-bottom">1px</xsl:attribute>
											
			       						<xsl:attribute name="font-weight">bold</xsl:attribute>
										Document name:
									</fo:block>
								</fo:table-cell>
								<fo:table-cell>
									<fo:block>
										<xsl:attribute name="margin-top">1px</xsl:attribute>
										<xsl:attribute name="margin-bottom">1px</xsl:attribute>
											
										<xsl:value-of select="dss:DocumentName"/>
									</fo:block>
								</fo:table-cell>
							</fo:table-row>
						</fo:table-body>
					</fo:table>
				</fo:block-container>
	       	</fo:block-container>
	       	
    	</fo:block-container>
    	
	</xsl:template>

	<xsl:template match="dss:ContainerType">
		<fo:table-row>
			<xsl:attribute name="margin-top">1px</xsl:attribute>
			<xsl:attribute name="margin-bottom">1px</xsl:attribute>
			<fo:table-cell>
				<fo:block>
					<xsl:attribute name="margin-top">1px</xsl:attribute>
					<xsl:attribute name="margin-bottom">1px</xsl:attribute>

					<xsl:attribute name="font-weight">bold</xsl:attribute>
					Container type:
				</fo:block>
			</fo:table-cell>
			<fo:table-cell>
				<fo:block>
					<xsl:attribute name="margin-top">1px</xsl:attribute>
					<xsl:attribute name="margin-bottom">1px</xsl:attribute>

					<xsl:value-of select="dss:ContainerType"/>
				</fo:block>
			</fo:table-cell>
		</fo:table-row>
	</xsl:template>

	<xsl:template match="dss:PDFAInfo">

		<fo:table-row>
			<xsl:attribute name="margin-top">1px</xsl:attribute>
			<xsl:attribute name="margin-bottom">1px</xsl:attribute>
			<fo:table-cell>
				<fo:block>
					<xsl:attribute name="margin-top">1px</xsl:attribute>
					<xsl:attribute name="margin-bottom">1px</xsl:attribute>

					<xsl:attribute name="font-weight">bold</xsl:attribute>
					PDF/A Profile:
				</fo:block>
			</fo:table-cell>
			<fo:table-cell>
				<fo:block>
					<xsl:attribute name="margin-top">1px</xsl:attribute>
					<xsl:attribute name="margin-bottom">1px</xsl:attribute>

					<xsl:value-of select="dss:PDFAProfile"/>
					<xsl:choose>
						<xsl:when test="@valid = 'true'"> (valid)</xsl:when>
						<xsl:otherwise> (failed)</xsl:otherwise>
					</xsl:choose>
				</fo:block>
			</fo:table-cell>
		</fo:table-row>

		<xsl:if test="dss:ValidationMessages">
			<fo:table-row>
				<xsl:attribute name="margin-top">1px</xsl:attribute>
				<xsl:attribute name="margin-bottom">1px</xsl:attribute>
				<fo:table-cell>
					<fo:block>
						<xsl:attribute name="margin-top">1px</xsl:attribute>
						<xsl:attribute name="margin-bottom">1px</xsl:attribute>

						<xsl:attribute name="font-weight">bold</xsl:attribute>
						PDF/A Validation Errors:
					</fo:block>
				</fo:table-cell>
				<fo:table-cell>
					<xsl:apply-templates select="dss:ValidationMessages/dss:Error"/>
				</fo:table-cell>
			</fo:table-row>
		</xsl:if>

	</xsl:template>
	 
    <xsl:template match="dss:Semantic">
    
    	<fo:table table-layout="fixed">
    	
			<fo:table-column>
				<xsl:attribute name="column-width">30%</xsl:attribute>
			</fo:table-column>
			<fo:table-column>
				<xsl:attribute name="column-width">70%</xsl:attribute>
			</fo:table-column>
    	
			<fo:table-body>
				<xsl:attribute name="start-indent">0</xsl:attribute>
				<xsl:attribute name="end-indent">0</xsl:attribute>
				
		    	<fo:table-row>
					<xsl:attribute name="margin-top">2px</xsl:attribute>
					<xsl:attribute name="margin-bottom">2px</xsl:attribute>
					<fo:table-cell>
						<xsl:attribute name="display-align">center</xsl:attribute>
						
						<fo:block>
		    				<xsl:attribute name="font-weight">bold</xsl:attribute>
    						<xsl:attribute name="font-size">7pt</xsl:attribute>
							<xsl:attribute name="margin-top">2px</xsl:attribute>
       						<xsl:attribute name="margin-bottom">2px</xsl:attribute>
		    				
							<xsl:value-of select="@Key"/>
						</fo:block>
					</fo:table-cell>
					<fo:table-cell>
						<xsl:attribute name="display-align">center</xsl:attribute>
						
						<fo:block>
		    				<xsl:attribute name="font-weight">normal</xsl:attribute>
							<xsl:attribute name="font-size">7pt</xsl:attribute>
							<xsl:attribute name="margin-top">2px</xsl:attribute>
       						<xsl:attribute name="margin-bottom">2px</xsl:attribute>
							
							<xsl:value-of select="."/>
						</fo:block>
					</fo:table-cell>
				</fo:table-row>
			</fo:table-body>
		</fo:table>    
    
    </xsl:template>

	<xsl:template name="formatdate">
		<xsl:param name="DateTimeStr" />

		<xsl:variable name="date">
			<xsl:value-of select="substring-before($DateTimeStr,'T')" />
		</xsl:variable>

		<xsl:variable name="after-T">
			<xsl:value-of select="substring-after($DateTimeStr,'T')" />
		</xsl:variable>

		<xsl:variable name="time">
			<xsl:value-of select="substring-before($after-T,'Z')" />
		</xsl:variable>

		<xsl:choose>
			<xsl:when test="string-length($date) &gt; 0 and string-length($time) &gt; 0">
				<xsl:value-of select="concat($date,' ', $time, ' (UTC)')" />
			</xsl:when>
			<xsl:when test="string-length($date) &gt; 0">
				<xsl:value-of select="$date" />
			</xsl:when>
			<xsl:when test="string-length($time) &gt; 0">
				<xsl:value-of select="$time" />
			</xsl:when>
			<xsl:otherwise>-</xsl:otherwise>
		</xsl:choose>
	</xsl:template>
	
</xsl:stylesheet>