<?xml version="1.0" encoding="UTF-8"?>

<xsl:stylesheet version="1.0"
xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:template match="/">
	<packets>
	<xsl:for-each select="//packet">
		<xsl:if test="proto[@name='icmp'] != ''">
		<packet>
			<xsl:attribute name="nodeuniq">
				<xsl:value-of select="concat('macsrc=', proto/field[@name='eth.src']/@value,';','macdst=', proto/field[@name='eth.dst']/@value,';','ipsrc=', proto/field[@name='ip.src']/@value,';','ipdst=', proto/field[@name='ip.dst']/@value,';','protoName=icmp')"/>
		    </xsl:attribute>
		
			<xsl:for-each select="proto[@name='icmp']">
				<xsl:apply-templates select='field' />
			</xsl:for-each><!-- ends proto[@name='icmp' -->
	    </packet>
    </xsl:if>
    </xsl:for-each> <!-- ends //packet -->
  </packets>
</xsl:template>

<xsl:template match="field">
	<field>			
		<mshowname><xsl:value-of select="@showname" /></mshowname>
		<msize><xsl:value-of select="@size" /></msize>
		<mshow><xsl:value-of select="@show" /></mshow>
		<mpos><xsl:value-of select="@pos" /></mpos>
		<mvalue><xsl:value-of select="@value" /></mvalue>
		<munmaskedvalue><xsl:value-of select="@unmaskedvalue" /></munmaskedvalue>
+		<!--<mname><xsl:value-of select="@name" /></mname>-->
+		<mname><xsl:value-of select="concat(@name,'.',@pos)" /></mname>
	</field>
	<xsl:apply-templates select='field' />
</xsl:template>

</xsl:stylesheet> 