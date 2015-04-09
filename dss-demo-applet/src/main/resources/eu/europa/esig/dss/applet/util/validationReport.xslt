<?xml version="1.0" encoding="UTF-8" ?>
<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns="http://www.w3.org/1999/xhtml"
                xmlns:dss="http://dss.esig.europa.eu/validation/diagnostic">

    <xsl:output method="xml"
                doctype-system="http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd"
                doctype-public="-//W3C//DTD XHTML 1.0 Transitional//EN" indent="yes"/>
    <xsl:template match="/dss:ValidationData">
        <html>
            <head>
                <title>Validation Simple Report</title>
                <style type="text/css">
                    html {
                        margin: 0;
                    }

                    body {
	                    font-family: Calibri;
	                    margin: 25px;
                    }

                    .signature-title {
                        margin: 0;
                        border-bottom: 1px dotted black;

                    }

                    div.signature-content {
                        margin-left: 1em;
                        padding-left: 1em;
                        border: 1px dotted black;
                        border-top: 0;
                    }

                    .conclusion-title {
                        clear: both;
                        margin: 0;
                        float: left;
                        font-weight: bolder;
                    }

                    .conclusion-content {
                        float: left;
                    }

                    .basic-building-block-item {
                        margin: 0;
                        padding: 1em;
                    }

                    .basic-building-block-item-title {
                        margin: 0;
                        border-bottom: 1px dotted black;

                    }

                    .basic-building-block-item-content {
                        margin: 0 0 0 1em;
                        padding-left: 1em;
                        border: 1px dotted black;
                        border-top: 0;
                    }

                    .basic-building-block-item-constraint {

                    }

                    .basic-building-block-item-constraint-name {
                    }

                    .basic-building-block-item-constraint-value {
                        margin-left: 2em;
                    }

                    dl {
                        margin: 0;
                    }

                    dl dt {
                        margin: 0;
                        width: 70%;
                        clear: left;
                        float: left;
                    }

                    dl dd {
                        margin: 0;
                        width: 20%;
                        float: left;

                    }

                    .clearfix {
                        clear: both;
                        height: 0;
                        width: 0;
                        overflow: hidden;
                    }

                    .timestamp {
                        margin: 0 0 0 1em;
                        padding: 1em;
                        border: 1px dotted black;
                        border-top: 0;

                    }

                    .timestamp .basic-building-block-title {
                        display: none;
                    }

                </style>
            </head>
            <body>
                <h1>Validation Report</h1>
                <xsl:apply-templates/>
            </body>
        </html>
    </xsl:template>

    <xsl:template match="dss:BasicBuildingBlocks">
        <h2 class="basic-building-block-title">Basic Building Blocks</h2>
        <div class="basic-building-block-content">
            <xsl:apply-templates/>
        </div>
    </xsl:template>

    <xsl:template match="dss:BasicValidationData">
        <h2>Basic Validation Data</h2>
        <xsl:apply-templates/>
    </xsl:template>

    <xsl:template match="dss:TimestampValidationData">
        <h2>Timestamp Validation Data</h2>
        <xsl:apply-templates/>
    </xsl:template>

    <xsl:template match="dss:AdESTValidationData">
        <h2>AdES-T Validation Data</h2>
        <xsl:apply-templates/>
    </xsl:template>

    <xsl:template match="dss:LongTermValidationData">
        <h2>Long Term Validation Data</h2>
        <xsl:apply-templates/>
    </xsl:template>

    <xsl:template match="dss:AdESTValidationData/dss:Signature|dss:LongTermValidationData/dss:Signature">
        <h3 class="signature-title" xml:space="preserve">Signature
            <xsl:value-of select="@Id"/>:
            <xsl:call-template name="signature-conclusion">
                <xsl:with-param name="Conclusion" select="dss:Conclusion" />
            </xsl:call-template>
        </h3>
        <div class="clearfix">&#160;</div>
        <div class="signature-content">
            <xsl:apply-templates/>
            <div class="clearfix">&#160;</div>
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
        <h3 class="signature-title" xml:space="preserve">Signature
            <xsl:value-of select="@Id"/>:

            <xsl:call-template name="signature-conclusion">
                    <xsl:with-param name="Conclusion" select="dss:Conclusion" />
            </xsl:call-template>
        </h3>
        <xsl:if test="count(child::*[name(.)!='Conclusion']) &gt; 0">
            <div class="signature-content">
                <xsl:apply-templates/>
            </div>
        </xsl:if>
    </xsl:template>

    <xsl:template name="signature-conclusion">
        <xsl:param name="Conclusion"/>
        <xsl:value-of select="$Conclusion/dss:Indication"/>
        <xsl:if test="string-length($Conclusion/dss:SubIndication) &gt; 0">.
            <xsl:value-of select="$Conclusion/dss:SubIndication"/>
        </xsl:if>
    </xsl:template>

    <xsl:template match="dss:ISC|dss:VCI|dss:CV|dss:SAV|dss:XCV">
        <div class="basic-building-block-item">
            <h4 class="basic-building-block-item-title">
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
                        <xsl:value-of select="name(.)"/>
                    </xsl:otherwise>
                </xsl:choose>
                :
                <xsl:call-template name="signature-conclusion">
                    <xsl:with-param name="Conclusion" select="dss:Conclusion"/>
                </xsl:call-template>
            </h4>
            <div class="basic-building-block-item-content">
                <xsl:apply-templates/>
            </div>
            <div class="clearfix">&#160;</div>
        </div>
    </xsl:template>


    <xsl:template match="dss:Constraint">
        <div class="basic-building-block-item-constraint">
            <span class="basic-building-block-item-constraint-name">
                <xsl:value-of select="dss:Name"/>
            </span>
            <span class="basic-building-block-item-constraint-value">
                <xsl:value-of select="dss:Status"/>
            </span>
        </div>
        <xsl:apply-templates select="dss:Info"/>
    </xsl:template>

    <xsl:template match="dss:Info">
        <div class="basic-building-block-item-constraint">
            <span class="basic-building-block-item-constraint-name">
	            <xsl:value-of select="concat(' - ',name(@*[1]),'=',@*)"/>
            </span>
        </div>
    </xsl:template>

  <xsl:template match="dss:Error">
    <div class="basic-building-block-item-constraint">
      <span class="basic-building-block-item-constraint-name">
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
      </span>
    </div>
  </xsl:template>
  <xsl:template match="dss:Warning">
    <div class="basic-building-block-item-constraint">
      <span class="basic-building-block-item-constraint-name">
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
      </span>
    </div>
  </xsl:template>

  <xsl:template match="dss:Info">
    <div class="basic-building-block-item-constraint">
      <span class="basic-building-block-item-constraint-name">
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
      </span>
    </div>
  </xsl:template>

    <xsl:template match="*">
        <xsl:comment>
            Ignored tag:
            <xsl:value-of select="name()"/>
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
