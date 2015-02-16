<?xml version="1.0" encoding="UTF-8" ?>
<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns="http://www.w3.org/1999/xhtml"
                xmlns:dss="http://dss.markt.ec.europa.eu/validation/diagnostic">

    <xsl:output method="xml"
                doctype-system="http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd"
                doctype-public="-//W3C//DTD XHTML 1.0 Transitional//EN" indent="yes"/>

    <xsl:template match="/dss:SimpleReport">
        <html>
            <head>
                <title>Validation Simple Report</title>
                <style type="text/css">
                    body {
                        font-family: Calibri;
	                    font-size: 100%;
                    }

                    th, td {
                        text-align: left;
                        vertical-align: top;
                    }

                    th {
                        font-weight: inherit;
                        width: 20%;
                    }

                    td {
                        width: 80%;
                    }

                    tr.validationPolicy .validationPolicy-name {
                        font-weight: bold;
                    }

                    tr.validationPolicy .validationPolicy-description {
                        font-size: 80%;
                        font-style: italic;
                    }

                    tr.signature-start, tr.signature-start th, tr.signature-start td {
                        border-top: 1px solid gray;
                    }

                    th.indication {
                        font-weight: bold;
                    }

                    th.indication .indication-icon {
                        font-size:110%;
                        margin-right: 0.5em;
                        font-style: italic;
                    }

                    .VALID {
                        color: green;
                    }

                    .INDETERMINATE {
                        color: orangered;
                    }

                    .INVALID {
                        color: red;
                    }

                    td.signatureLevel {
                        font-weight: bold;
                    }

                    tr.documentInformation {
                        color: darkgreen;
                    }

                    tr.documentInformation th {
                        padding-left: 2em;
                    }

                    tr.documentInformation-header, tr.documentInformation-header th, tr.documentInformation-header td {
                        border-top: 1px solid gray;
                    }

                    tr.documentInformation-header th {
                        padding-left: 0;
                        font-weight: bold;
                    }
                </style>
            </head>
            <body>
                <table>
                    <xsl:apply-templates/>
                    <xsl:call-template name="documentInformation"/>
                </table>
            </body>


        </html>
    </xsl:template>


    <xsl:template match="dss:DocumentName"/>
    <xsl:template match="dss:SignatureFormat"/>
    <xsl:template match="dss:SignaturesCount"/>
    <xsl:template match="dss:ValidSignaturesCount"/>

    <xsl:template match="dss:Policy">
        <tr class="validationPolicy">
            <th>Validation Policy:</th>
            <td>
                <div class="validationPolicy-name">
                    <xsl:value-of select="dss:PolicyName"/>
                </div>
                <div class="validationPolicy-description">
                    <xsl:value-of select="dss:PolicyDescription"/>
                </div>
            </td>
        </tr>

    </xsl:template>

    <xsl:template match="dss:ValidationTime"/>

    <xsl:template match="dss:Signature">
        <xsl:variable name="indicationClass" select="dss:Indication/text()"/>
        <tr class="signature-start">
            <th>
                <xsl:attribute name="class" xml:space="preserve">indication <xsl:value-of select="$indicationClass"/></xsl:attribute>
                <span class="indication-icon">
                    <xsl:choose>
                        <xsl:when test="$indicationClass='VALID'">V</xsl:when>
                        <xsl:when test="$indicationClass='INDETERMINATE'">?</xsl:when>
                        <xsl:when test="$indicationClass='INVALID'">X</xsl:when>
                    </xsl:choose>
                </span>
                <xsl:value-of select="dss:Indication"/>
            </th>
            <td class="signatureLevel">
                <xsl:value-of select="dss:SignatureLevel"/>
            </td>
        </tr>
        <xsl:apply-templates select="dss:SubIndication">
            <xsl:with-param name="indicationClass" select="$indicationClass"/>
        </xsl:apply-templates>
	    <xsl:apply-templates select="dss:Error">
		    <xsl:with-param name="indicationClass" select="$indicationClass"/>
	    </xsl:apply-templates>
	    <xsl:apply-templates select="dss:Warning">
		    <xsl:with-param name="indicationClass" select="$indicationClass"/>
	    </xsl:apply-templates>
        <xsl:apply-templates select="dss:Info">
            <xsl:with-param name="indicationClass" select="$indicationClass"/>
        </xsl:apply-templates>
        <tr>
            <th>Signature ID:</th>
            <td>
                <xsl:value-of select="@Id"/>
            </td>
        </tr>
        <tr>
            <th>Signature format:</th>
            <td>
                <xsl:value-of select="@SignatureFormat"/>
            </td>
        </tr>
        <tr>
            <th>Signed by:</th>
            <td>
                <xsl:value-of select="dss:SignedBy"/>
            </td>
        </tr>
        <tr>
            <th>On claimed time:</th>
            <td>
                <div>
                    <xsl:value-of select="dss:SigningTime"/>
                </div>
                <div>
                    The validation of the signature, of its supporting certificates and of the related certification
                    path has been performed from this reference time.
                </div>
            </td>
        </tr>
        <tr>
            <th>Signature position:</th>
            <td>
                <xsl:value-of select="count(preceding-sibling::dss:Signature) + 1"/> out of
                <xsl:value-of select="count(ancestor::*/dss:Signature)"/>
            </td>
        </tr>
        <xsl:for-each select="./dss:SignatureScopes/dss:SignatureScope">
          <tr>
            <th>Signature scope:</th>
            <td>
              <div>
                <xsl:value-of select="@name"/> (<xsl:value-of select="@scope"/>)
              </div>
              <div>
                <xsl:value-of select="."/>
              </div>
            </td>
          </tr>
        </xsl:for-each>
    </xsl:template>

	<xsl:template match="dss:SubIndication">
		<xsl:param name="indicationClass" />
		<tr class="info">
			<th></th>
			<td class="{$indicationClass}">
				<xsl:value-of select="concat(' - ',@*)"/>
				<xsl:apply-templates/>
			</td>
		</tr>
	</xsl:template>

	<xsl:template match="dss:Error">
		<xsl:param name="indicationClass" />
		<tr class="info">
			<th></th>
			<td class="{$indicationClass}">
				<xsl:variable name="txt" select="concat(' - E: ',name(@*[not(name()='NameId')][1]),'=',@*[not(name()='NameId')],' / ')"/>
				<xsl:variable name="ntxt">
					<xsl:call-template name="string-replace-all">
						<xsl:with-param name="text" select="$txt" />
						<xsl:with-param name="replace" select="'= /'" />
						<xsl:with-param name="by" select="''"/>
					</xsl:call-template>
				</xsl:variable>
				<xsl:value-of select="$ntxt"/>
				<xsl:apply-templates/>
			</td>
		</tr>
	</xsl:template>

	<xsl:template match="dss:Warning">
		<xsl:param name="indicationClass" />
		<tr class="info">
			<th></th>
			<td class="{$indicationClass}">
				<xsl:variable name="txt" select="concat(' - W: ',name(@*[not(name()='NameId')][1]),'=',@*[not(name()='NameId')],' / ')"/>
				<xsl:variable name="ntxt">
					<xsl:call-template name="string-replace-all">
						<xsl:with-param name="text" select="$txt" />
						<xsl:with-param name="replace" select="'= /'" />
						<xsl:with-param name="by" select="''"/>
					</xsl:call-template>
				</xsl:variable>
				<xsl:value-of select="$ntxt"/>
				<xsl:apply-templates/>
			</td>
		</tr>
	</xsl:template>

	<xsl:template match="dss:Info">
		<xsl:param name="indicationClass" />
		<tr class="info">
			<th></th>
			<td class="{$indicationClass}">
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
			</td>
		</tr>
	</xsl:template>

	<xsl:template name="documentInformation">
        <tr class="documentInformation documentInformation-header">
            <th colspan="2">Document Information</th>
        </tr>
        <tr class="documentInformation documentInformation-type">
            <th>Signatures status:</th>
            <td>
                <xsl:choose>
                    <xsl:when test="dss:ValidSignaturesCount = dss:SignaturesCount">
                        <xsl:attribute name="class" xml:space="preserve">VALID</xsl:attribute>
                    </xsl:when>
                    <xsl:otherwise>
                        <xsl:attribute name="class" xml:space="preserve">INDETERMINATE</xsl:attribute>
                    </xsl:otherwise>
                </xsl:choose>
                <xsl:value-of select="dss:ValidSignaturesCount"/> valid signatures, out of <xsl:value-of select="dss:SignaturesCount"/>
            </td>
        </tr>
        <tr class="documentInformation documentInformation-type">
            <th>Document name:</th>
            <td>
                <xsl:value-of select="dss:DocumentName"/>
            </td>
        </tr>
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
