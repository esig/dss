/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.enumerations;

import java.math.BigInteger;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.Map;

/**
 * Represents an elliptic curve.
 * NOTE: Values for these parameters are taken from
 * {@code <a href="https://bitbucket.org/b_c/jose4j/src/master/src/main/java/org/jose4j/keys/EllipticCurves.java">EllipticCurves.java</a>}
 * class of jose4j library. The values are also present in FIPS PUB 186-3.
 *
 */
public enum EllipticCurve {

    /** P-256 curve */
    P_256("P-256", 32),

    /** P-384 curve */
    P_384("P-384", 48),

    /** P-512 curve */
    P_521("P-521", 66),

    /** X25519 */
    X25519("X25519", 32),

    /** X448 */
    X448("X448", 56),

    /** EdDSA 25519 */
    ED25519("Ed25519", 32),

    /** EdDSA 448 */
    ED448("Ed448", 57),

    /** SECP-256k1 curve */
    SECP_256K1("secp256k1", 32),

    /** Brainpool P-256 R1 curve */
    BRAINPOOL_P256_R1("brainpoolP256r1", 32),

    /** Brainpool P-320 R1 curve */
    BRAINPOOL_P320_R1("brainpoolP320r1", 40),

    /** Brainpool P-384 R1 curve */
    BRAINPOOL_P384_R1("brainpoolP384r1", 48),

    /** Brainpool P-512 R1 curve */
    BRAINPOOL_P512_R1("brainpoolP512r1", 64);

    /** Name of the elliptic curve */
    private final String label;

    /** Size in bytes of the elliptic curve */
    private final int size;

    /**
     * Default constructor
     *
     * @param label {@link String}
     */
    EllipticCurve(final String label, final int size) {
        this.label = label;
        this.size = size;
    }

    private static final int COFACTOR = 1;

    private static final ECParameterSpec P256 = new ECParameterSpec(
            new java.security.spec.EllipticCurve(
                    // field the finite field that this elliptic curve is over.
                    new ECFieldFp(new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853951")),
                    // a the first coefficient of this elliptic curve.
                    new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853948"),
                    // b the second coefficient of this elliptic curve.
                    new BigInteger("41058363725152142129326129780047268409114441015993725554835256314039467401291")
            ),
            //g the generator which is also known as the base point.
            new ECPoint(
                    // gx
                    new BigInteger("48439561293906451759052585252797914202762949526041747995844080717082404635286"),
                    // gy
                    new BigInteger("36134250956749795798585127919587881956611106672985015071877198253568414405109")
            ),
            // Order n
            new BigInteger("115792089210356248762697446949407573529996955224135760342422259061068512044369"),
            COFACTOR);

    private static final ECParameterSpec P384 = new ECParameterSpec(
            new java.security.spec.EllipticCurve(
                    // field the finite field that this elliptic curve is over.
                    new ECFieldFp(new BigInteger("39402006196394479212279040100143613805079739270465" +
                            "44666794829340424572177149687032904726608825893800" +
                            "1861606973112319")),
                    // a the first coefficient of this elliptic curve.
                    new BigInteger("39402006196394479212279040100143613805079739270465" +
                            "44666794829340424572177149687032904726608825893800" +
                            "1861606973112316"),
                    // b the second coefficient of this elliptic curve.
                    new BigInteger("27580193559959705877849011840389048093056905856361" +
                            "56852142870730198868924130986086513626076488374510" +
                            "7765439761230575")
            ),
            //g the generator which is also known as the base point.
            new ECPoint(
                    // gx
                    new BigInteger("26247035095799689268623156744566981891852923491109" +
                            "21338781561590092551885473805008902238805397571978" +
                            "6650872476732087"),
                    // gy
                    new BigInteger("83257109614890299855467512895201081792878530488613" +
                            "15594709205902480503199884419224438643760392947333" +
                            "078086511627871")
            ),
            // Order n
            new BigInteger("39402006196394479212279040100143613805079739270465446667946905279627" +
                    "659399113263569398956308152294913554433653942643"),
            COFACTOR);

    private static final ECParameterSpec P521 = new ECParameterSpec(
            new java.security.spec.EllipticCurve(
                    // field the finite field that this elliptic curve is over.
                    new ECFieldFp(new BigInteger("68647976601306097149819007990813932172694353001433" +
                            "05409394463459185543183397656052122559640661454554" +
                            "97729631139148085803712198799971664381257402829111" +
                            "5057151")),
                    // a the first coefficient of this elliptic curve.
                    new BigInteger("68647976601306097149819007990813932172694353001433" +
                            "05409394463459185543183397656052122559640661454554" +
                            "97729631139148085803712198799971664381257402829111" +
                            "5057148"),
                    // b the second coefficient of this elliptic curve.
                    new BigInteger("10938490380737342745111123907668055699362075989516" +
                            "83748994586394495953116150735016013708737573759623" +
                            "24859213229670631330943845253159101291214232748847" +
                            "8985984")
            ),
            //g the generator which is also known as the base point.
            new ECPoint(
                    // gx
                    new BigInteger("26617408020502170632287687167233609607298591687569" +
                            "73147706671368418802944996427808491545080627771902" +
                            "35209424122506555866215711354557091681416163731589" +
                            "5999846"),
                    // gy
                    new BigInteger("37571800257700204635455072244911836035944551347697" +
                            "62486694567779615544477440556316691234405012945539" +
                            "56214444453728942852258566672919658081012434427757" +
                            "8376784")
            ),
            // Order n
            new BigInteger("68647976601306097149819007990813932172694353001433" +
                    "05409394463459185543183397655394245057746333217197" +
                    "53296399637136332111386476861244038034037280889270" +
                    "7005449"),
            COFACTOR);

    private static final ECParameterSpec SECP256K1 = new ECParameterSpec(
            new java.security.spec.EllipticCurve(
                    // field the finite field that this elliptic curve is over.
                    new ECFieldFp(new BigInteger("115792089237316195423570985008687907853269984665640564039457584007908834671663")),
                    // a the first coefficient of this elliptic curve.
                    BigInteger.valueOf(0),
                    // b the second coefficient of this elliptic curve.
                    BigInteger.valueOf(7)
            ),
            //g the generator which is also known as the base point.
            new ECPoint(
                    // gx
                    new BigInteger("55066263022277343669578718895168534326250603453777594175500187360389116729240"),
                    // gy
                    new BigInteger("32670510020758816978083085130507043184471273380659243275938904335757337482424")
            ),
            // Order n
            new BigInteger("115792089237316195423570985008687907852837564279074904382605163141518161494337"),
            COFACTOR);

    /* Values below are taken from RFC 5639 */

    // Curve-ID: brainpoolP256r1
    private static final ECParameterSpec BP256 = new ECParameterSpec(
            new java.security.spec.EllipticCurve(
                    // P
                    new ECFieldFp(new BigInteger("A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377", 16)),
                    // A
                    new BigInteger("7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9", 16),
                    // B
                    new BigInteger("26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6", 16)
            ),
            //g the generator which is also known as the base point.
            new ECPoint(
                    // X
                    new BigInteger("8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262", 16),
                    // Y
                    new BigInteger("547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997", 16)
            ),
            // Q
            new BigInteger("A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7", 16),
            COFACTOR);

    // Curve-ID: brainpoolP320r1
    private static final ECParameterSpec BP320 = new ECParameterSpec(
            new java.security.spec.EllipticCurve(
                    // P
                    new ECFieldFp(new BigInteger("D35E472036BC4FB7E13C785ED201E065F98FCFA6F6F40DEF4F92B9EC7893EC28FCD412B1F1B32E27", 16)),
                    // A
                    new BigInteger("3EE30B568FBAB0F883CCEBD46D3F3BB8A2A73513F5EB79DA66190EB085FFA9F492F375A97D860EB4", 16),
                    // B
                    new BigInteger("520883949DFDBC42D3AD198640688A6FE13F41349554B49ACC31DCCD884539816F5EB4AC8FB1F1A6", 16)
            ),
            //g the generator which is also known as the base point.
            new ECPoint(
                    // X
                    new BigInteger("43BD7E9AFB53D8B85289BCC48EE5BFE6F20137D10A087EB6E7871E2A10A599C710AF8D0D39E20611", 16),
                    // Y
                    new BigInteger("14FDD05545EC1CC8AB4093247F77275E0743FFED117182EAA9C77877AAAC6AC7D35245D1692E8EE1", 16)
            ),
            // Q
            new BigInteger("D35E472036BC4FB7E13C785ED201E065F98FCFA5B68F12A32D482EC7EE8658E98691555B44C59311", 16),
            COFACTOR);

    // Curve-ID: brainpoolP384r1
    private static final ECParameterSpec BP384 = new ECParameterSpec(
            new java.security.spec.EllipticCurve(
                    // P
                    new ECFieldFp(new BigInteger("8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53", 16)),
                    // A
                    new BigInteger("7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826", 16),
                    // B
                    new BigInteger("04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11", 16)
            ),
            //g the generator which is also known as the base point.
            new ECPoint(
                    // X
                    new BigInteger("1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E", 16),
                    // Y
                    new BigInteger("8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315", 16)
            ),
            // Q
            new BigInteger("8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565", 16),
            COFACTOR);

    // Curve-ID: brainpoolP512r1
    private static final ECParameterSpec BP512 = new ECParameterSpec(
            new java.security.spec.EllipticCurve(
                    // P
                    new ECFieldFp(new BigInteger("AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308" +
                            "717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3", 16)),
                    // A
                    new BigInteger("7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863" +
                            "BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA", 16),
                    // B
                    new BigInteger("3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117" +
                            "A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723", 16)
            ),
            //g the generator which is also known as the base point.
            new ECPoint(
                    // X
                    new BigInteger("81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D009" +
                            "8EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822", 16),
                    // Y
                    new BigInteger("7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F81" +
                            "11B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892", 16)
            ),
            // Q
            new BigInteger("AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308" +
                    "70553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069", 16),
            COFACTOR);

    /**
     * Map of elliptic curve pre-configured parameters
     */
    private static final Map<EllipticCurve, ECParameterSpec> ELLIPTIC_CURVE_PARAMETERS = registerParameters();

    private static Map<EllipticCurve, ECParameterSpec> registerParameters() {
        Map<EllipticCurve, ECParameterSpec> parameters = new EnumMap<>(EllipticCurve.class);
        parameters.put(P_256, P256);
        parameters.put(P_384, P384);
        parameters.put(P_521, P521);
        parameters.put(SECP_256K1, SECP256K1);
        parameters.put(BRAINPOOL_P256_R1, BP256);
        parameters.put(BRAINPOOL_P320_R1, BP320);
        parameters.put(BRAINPOOL_P384_R1, BP384);
        parameters.put(BRAINPOOL_P512_R1, BP512);
        return parameters;
    }

    /**
     * COSE labels as defined in {@code <a href="https://www.iana.org/assignments/cose/cose.xhtml">IANA registry</a>}
     */
    private static final Map<EllipticCurve, Long> ELLIPTIC_CURVE_COSE_VALUES = registerCOSEValues();

    /**
     * Reversed map of Elliptic Curves for COSE values
     */
    private static final Map<Long, EllipticCurve> ELLIPTIC_CURVE_FOR_COSE_VALUES = registerEllipticCurvesForCoseValues();

    private static Map<EllipticCurve, Long> registerCOSEValues() {
        Map<EllipticCurve, Long> valuesMap = new EnumMap<>(EllipticCurve.class);
        valuesMap.put(P_256, 1L);
        valuesMap.put(P_384, 2L);
        valuesMap.put(P_521, 3L);
        valuesMap.put(X25519, 4L);
        valuesMap.put(X448, 5L);
        valuesMap.put(ED25519, 6L);
        valuesMap.put(ED448, 7L);
        valuesMap.put(SECP_256K1, 8L);
        valuesMap.put(BRAINPOOL_P256_R1, 256L);
        valuesMap.put(BRAINPOOL_P320_R1, 257L);
        valuesMap.put(BRAINPOOL_P384_R1, 258L);
        valuesMap.put(BRAINPOOL_P512_R1, 259L);
        return valuesMap;
    }

    private static Map<Long, EllipticCurve> registerEllipticCurvesForCoseValues() {
        Map<Long, EllipticCurve> coseValuesMap = new HashMap<>();
        for (Map.Entry<EllipticCurve, Long> entry : ELLIPTIC_CURVE_COSE_VALUES.entrySet()) {
            coseValuesMap.put(entry.getValue(), entry.getKey());
        }
        return coseValuesMap;
    }

    /**
     * Map of elliptic curves and corresponding OIDs
     */
    private static final Map<EllipticCurve, String> ELLIPTIC_CURVE_OIDS = registerOIDs();

    /**
     * Reversed map of Elliptic Curves for OIDs
     */
    private static final Map<String, EllipticCurve> ELLIPTIC_CURVE_FOR_OID = registerEllipticCurvesForOIDs();

    private static Map<EllipticCurve, String> registerOIDs() {
        Map<EllipticCurve, String> oidsMap = new EnumMap<>(EllipticCurve.class);
        oidsMap.put(P_256, "1.2.840.10045.3.1.7");
        oidsMap.put(P_384, "1.3.132.0.34");
        oidsMap.put(P_521, "1.3.132.0.35");
        oidsMap.put(X25519, "1.3.101.110");
        oidsMap.put(X448, "1.3.101.111");
        oidsMap.put(ED25519, "1.3.101.112");
        oidsMap.put(ED448, "1.3.101.113");
        oidsMap.put(SECP_256K1, "1.2.840.10045.3.1.7");
        oidsMap.put(BRAINPOOL_P256_R1, "1.3.36.3.3.2.8.1.1.7");
        oidsMap.put(BRAINPOOL_P320_R1, "1.3.36.3.3.2.8.1.1.9");
        oidsMap.put(BRAINPOOL_P384_R1, "1.3.36.3.3.2.8.1.1.11");
        oidsMap.put(BRAINPOOL_P512_R1, "1.3.36.3.3.2.8.1.1.13");
        return oidsMap;
    }

    private static Map<String, EllipticCurve> registerEllipticCurvesForOIDs() {
        Map<String, EllipticCurve> coseValuesMap = new HashMap<>();
        for (Map.Entry<EllipticCurve, String> entry : ELLIPTIC_CURVE_OIDS.entrySet()) {
            coseValuesMap.put(entry.getValue(), entry.getKey());
        }
        return coseValuesMap;
    }

    /**
     * Gets a user-friendly label of the elliptic curve
     *
     * @return {@link String}
     */
    public String getLabel() {
        return label;
    }

    /**
     * Gets an elliptic curve for the given label (same as COSE name)
     *
     * @param label {@link String}
     * @return {@link EllipticCurve}
     */
    public static EllipticCurve forLabel(String label) {
        if (label == null) {
            return null;
        }
        for (EllipticCurve ellipticCurve : values()) {
            if (label.equals(ellipticCurve.label)) {
                return ellipticCurve;
            }
        }
        return null;
    }

    /**
     * Gets coordinate byte size for the elliptic curve
     *
     * @return coordinate size
     */
    public int getSize() {
        return size;
    }

    /**
     * Gets the elliptic curve parameter specification
     *
     * @return {@link ECParameterSpec}
     */
    public ECParameterSpec getParameter() {
        return ELLIPTIC_CURVE_PARAMETERS.get(this);
    }

    /**
     * Gets elliptic curve for the given parameter spec
     *
     * @param parameter {@link ECParameterSpec}
     * @return {@link EllipticCurve}
     */
    public static EllipticCurve forParameter(ECParameterSpec parameter) {
        if (parameter == null) {
            return null;
        }
        for (EllipticCurve ellipticCurve : values()) {
            ECParameterSpec ecParameter = ellipticCurve.getParameter();
            if (equalCurves(parameter, ecParameter)) {
                return ellipticCurve;
            }
        }
        return null;
    }

    private static boolean equalCurves(ECParameterSpec a, ECParameterSpec b) {
        if (a == null && b == null) {
            return true;
        }
        if (a == null || b == null) {
            return false;
        }

        // Compare field prime
        BigInteger p1 = ((ECFieldFp) a.getCurve().getField()).getP();
        BigInteger p2 = ((ECFieldFp) b.getCurve().getField()).getP();

        if (!p1.equals(p2)) {
            return false;
        }

        // Compare coefficients
        if (!a.getCurve().getA().equals(b.getCurve().getA())) {
            return false;
        }
        if (!a.getCurve().getB().equals(b.getCurve().getB())) {
            return false;
        }

        // Compare generator
        if (!a.getGenerator().getAffineX().equals(b.getGenerator().getAffineX())) {
            return false;
        }
        if (!a.getGenerator().getAffineY().equals(b.getGenerator().getAffineY())) {
            return false;
        }

        // Compare order
        if (!a.getOrder().equals(b.getOrder())) {
            return false;
        }

        return true;
    }

    /**
     * Gets the COSE value as defined in {@code <a href="https://www.iana.org/assignments/cose/cose.xhtml">IANA</a>}
     *
     * @return {@link Number}
     */
    public Number getCOSEValue() {
        return ELLIPTIC_CURVE_COSE_VALUES.get(this);
    }

    /**
     * Gets elliptic curve for the given COSE value
     *
     * @param value {@link Number}
     * @return {@link EllipticCurve}
     */
    public static EllipticCurve forCOSEValue(Number value) {
        if (value == null) {
            return null;
        }
        return ELLIPTIC_CURVE_FOR_COSE_VALUES.get(value.longValue());
    }

    /**
     * Gets the OID value
     *
     * @return {@link String}
     */
    public String getOID() {
        return ELLIPTIC_CURVE_OIDS.get(this);
    }

    /**
     * Gets elliptic curve for the given OID value
     *
     * @param oid {@link String}
     * @return {@link EllipticCurve}
     */
    public static EllipticCurve forOID(String oid) {
        return ELLIPTIC_CURVE_FOR_OID.get(oid);
    }

}
