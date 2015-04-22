<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:fo="http://www.w3.org/1999/XSL/Format">
	<xsl:output method="xml" indent="yes" />

	<xsl:template match="/">
		<fo:root>
			<fo:layout-master-set>
				<fo:simple-page-master>
					<xsl:attribute name="master-name">A4-portrait</xsl:attribute>
					<xsl:attribute name="page-height">29.7cm</xsl:attribute>
					<xsl:attribute name="page-width">21.0cm</xsl:attribute>
					<xsl:attribute name="margin">2cm</xsl:attribute>
					<fo:region-body />
				</fo:simple-page-master>
			</fo:layout-master-set>

			<fo:page-sequence>
				<xsl:attribute name="master-reference">A4-portrait</xsl:attribute>

				<fo:flow>
					<xsl:attribute name="flow-name">xsl-region-body</xsl:attribute>
					<fo:block>
						Hello World!
					</fo:block>
				</fo:flow>
			</fo:page-sequence>
		</fo:root>
	</xsl:template>
</xsl:stylesheet>