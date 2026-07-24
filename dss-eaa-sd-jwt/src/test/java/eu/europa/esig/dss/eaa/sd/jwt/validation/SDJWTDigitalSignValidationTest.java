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
package eu.europa.esig.dss.eaa.sd.jwt.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.validationreport.jaxb.SignerInformationType;

import static org.junit.jupiter.api.Assertions.assertTrue;

class SDJWTDigitalSignValidationTest extends AbstractSDJWTTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new InMemoryDocument("eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiIsImtpZCI6InlmcERQdTlkbC1sMFBHdlpEZzY3Mk9JTzRVYmc1NnpIWEhVLXY4SWo2ZzAiLCJ4NWMiOlsiTUlJRklUQ0NCS2VnQXdJQkFnSVVkU1VXOTZFYTdoYk0rQUtuellRcm1JSWlzME13Q2dZSUtvWkl6ajBFQXdNd1l6RUxNQWtHQTFVRUJoTUNVRlF4S2pBb0JnTlZCQW9NSVVScFoybDBZV3hUYVdkdUlFTmxjblJwWm1sallXUnZjbUVnUkdsbmFYUmhiREVvTUNZR0ExVUVBd3dmUkVsSFNWUkJURk5KUjA0Z1VWVkJURWxHU1VWRUlFTkJJRll4SUVSRlZqQWVGdzB5TlRBNU16QXhOak00TVRsYUZ3MHlPREE1TWpreE5qTTRNVGhhTUlIZU1Rc3dDUVlEVlFRR0V3SlFWREZETUVFR0ExVUVDd3c2UTJWeWRHbG1hV05oZEdVZ1VISnZabWxzWlNBdElGRjFZV3hwWm1sbFpDQkRaWEowYVdacFkyRjBaU0F0SUU5eVoyRnVhWHBoZEdsdmJqRVlNQllHQTFVRVlRd1BWa0ZVVUZRdE1USXpORFUyTnpnNU1SUXdFZ1lEVlFRS0RBdEVhV2RwZEdGc1UybG5iakVrTUNJR0NTcUdTSWIzRFFFSkFSWVZkMkZzYkdWMFFHUnBaMmwwWVd4emFXZHVMbkIwTVIwd0d3WURWUVFMREJSU1pXMXZkR1ZSVTBORVRXRnVZV2RsYldWdWRERVZNQk1HQTFVRUF3d01SRWxIU1ZSQlRDQlRTVWRPTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFdmN6WG12VnU2dDBTYmpjNTJ0S2FwaFJzbkZqbGUwYzdPNkJyMmxKQ1ZUWngzM0l1ZGFuelA5d3Rlck44Z2JZMUlhaVVaVVk5eHlpUTdHWTlBN3RaNUtPQ0Fyc3dnZ0szTUF3R0ExVWRFd0VCL3dRQ01BQXdId1lEVlIwakJCZ3dGb0FVRVJyUnl4NjN1VThyQVpjUmlOSVJOZ1Znb0wwd2daUUdDQ3NHQVFVRkJ3RUJCSUdITUlHRU1FNEdDQ3NHQVFVRkJ6QUNoa0pvZEhSd2N6b3ZMM0ZqWVMxMk1TMWtaWFl1WkdsbmFYUmhiSE5wWjI0dWNIUXZSRWxIU1ZSQlRGTkpSMDVSVlVGTVNVWkpSVVJEUVZZeExVUkZWaTV3TjJJd01nWUlLd1lCQlFVSE1BR0dKbWgwZEhCek9pOHZjV05oTFhZeExXUmxkaTVrYVdkcGRHRnNjMmxuYmk1d2RDOXZZM053TUNBR0ExVWRFUVFaTUJlQkZYZGhiR3hsZEVCa2FXZHBkR0ZzYzJsbmJpNXdkREJqQmdOVkhTQUVYREJhTURzR0N5c0dBUVFCZ2NkOEJBRUJNQ3d3S2dZSUt3WUJCUVVIQWdFV0htaDBkSEJ6T2k4dmNHdHBMV1JsZGk1a2FXZHBkR0ZzYzJsbmJpNXdkREFRQmc0ckJnRUVBWUhIZkFRQ0FnRUJCakFKQmdjRUFJdnNRQUVETUIwR0ExVWRKUVFXTUJRR0NDc0dBUVVGQndNQ0JnZ3JCZ0VGQlFjREJEQ0J4QVlJS3dZQkJRVUhBUU1FZ2Jjd2diUXdGUVlJS3dZQkJRVUhDd0l3Q1FZSEJBQ0w3RWtCQWpBSUJnWUVBSTVHQVFFd0NBWUdCQUNPUmdFRU1CTUdCZ1FBamtZQkJqQUpCZ2NFQUk1R0FRWUNNSElHQmdRQWprWUJCVEJvTURJV0xHaDBkSEJ6T2k4dmNXTmhMWFl4TFdSbGRpNWthV2RwZEdGc2MybG5iaTV3ZEM5UVJGTmZaVzR1Y0dSbUV3SmxiakF5Rml4b2RIUndjem92TDNGallTMTJNUzFrWlhZdVpHbG5hWFJoYkhOcFoyNHVjSFF2VUVSVFgzQjBMbkJrWmhNQ2NIUXdVd1lEVlIwZkJFd3dTakJJb0VhZ1JJWkNhSFIwY0hNNkx5OXhZMkV0ZGpFdFpHVjJMbVJwWjJsMFlXeHphV2R1TG5CMEwwUkpSMGxVUVV4VFNVZE9VVlZCVEVsR1NVVkVRMEZXTVMxRVJWWXVZM0pzTUIwR0ExVWREZ1FXQkJTREhHWDBzN2hXckFyOGxQYTBCakVIc0VrZHZEQU9CZ05WSFE4QkFmOEVCQU1DQmtBd0NnWUlLb1pJemowRUF3TURhQUF3WlFJeEFLK3B2WFJFc0VvS2pPQndrWENiSWs5K2NDNmFWa3M0K1NXT0loUW1aSmxCenZTNmIwbGRySldENGxHZSs0Rk0vUUl3Wm8vdzhCUFczR2FuK3RnWndCZzRQY1h6RHprenBDMHVKYlo3VHc2aTBoTUl1MkV4VVh0bGo3TjNVTzBlenI4LyJdfQ.eyJpc3MiOiJodHRwczovL2Rzd2FsbGV0b2lkYy1kZXYuZGlnaXRhbHNpZ24ucHQvZGlnaXRhbHNpZ24iLCJpYXQiOjE3NzE5NDUxNTgsIm5iZiI6MTc3MTk0NTE1OCwiZXhwIjoxODY2NjM5MzAzLCJ2Y3QiOiJ1cm46ZGlnaXRhbHNpZ246ZHNpZDoxIiwiaWQiOiIwM2FiYTIwOS0wZTA3LTRlMmItOGI1Ni0zNmM5NzljMTdhNzYiLCJjbmYiOnsiandrIjp7Imt0eSI6IkVDIiwieCI6ImlJaTFKZi12TW91aWpZZm9lSG9UTFFEWXlfVDQ4LVpXdGpPRUdNVDFGTEEiLCJ5IjoidGZUb0FWU0pYV1F3aW96ZTVObTZQMzVpWG44ZVpXWllrSi1PY3NObWVIYyIsImNydiI6IlAtMjU2IiwiYWxnIjoiRVMyNTYiLCJ1c2UiOiJzaWciLCJraWQiOiJtb3hMaTVsT292b0RTWUczOUh3R3R2S1ZSOF9KQm1BcFJxNWNraFAwb2pFIn19LCJfc2RfYWxnIjoic2hhLTI1NiIsIl9zZCI6WyJqVFI5QXdUMXl6MWl1VnVfeEozNkF1WUdiNGVyOVVuTXNCcm5CcG02cHg4IiwiZnZRU0tDSzNaV3V4Tm5yOE10LWxUUDRaQzM4RTNBNlZ3V0RFdmlCcFoxOCIsImJJNFowQWR0M1VIME43NjQxZWl0NVdUMUs5UWFfSXEtcDNRa0R5dUZYMWMiLCJzT0VfZWtKaUFNRE9UWlFVVkRuS241NjIzRXlfcmM2ajFYMVdmSjFxSFNZIiwiTko1ZWdrUWREVWFIaFFPcERISzBuR21HYWdHcF9rOEZHdnY0TS1EUUdKWSIsIjVOR1RQcEFPZ2Z1QW51WkoxU1dINnd6c2Y2WEhkc05oQjVMdm1fTktWQkUiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsiX3NkIjpbIm1WdHNxSVAtUEFzQU1iemNGTzBNb2NJWU5wYmRCOUFOX0wwMDNvNWV6bkkiLCI1N1A1LV9fVkNnUUtVZE1wU2dVQWhGVHdvd1ZMU1dZcU13dUc3THYxNUJvIiwiNURNd2UtcnJraVJrWVF0LVE0d3VySjVtaXo5SEx1UVl2azhHWndxTk9YSSIsIkVfeXNZbEhoM2ZwRkRRQWJqclg5NHdGT2RYRlJkQjdNTmxDb1hfYmgxRjAiLCIzb0poREtFOWQ4VmZjSlhBenNNMVZFRzJOeklacF9Rc3p2Tll2UnBscndJIiwiRVdwUlc1RHRaclI2Z25YVHpnTUc1ZEJ4V29FTmtNS2t4eGRFVnZmUmd3WSIsInBOcUo2N3JvcXBSNFBWN0FaY3NieVIxcU1FS1BXNXpqbWJsQzEzSmdtbUUiLCJkWHRkV09Cazdjc0lCYXVXTlRNT2Nub1dSY0FCcjB6UDNJNFBlWi1iWkV3IiwiZW9lX2txYUVQd25ZUnBvbTZnZ3g1QmF6ZW9oczFfa1BsSEJFWHgyYXFGYyIsIk05eWNwSVl4ZURjVnBkSDl3QkI4dzJybHMwMWhyaDVCQkpvSGZjcHVDWlEiLCJuQzUwejlueWZaQW54N3lZblVLNjZXMDRWTTM3NU9HeGNrckNNcmtKNC1nIiwibXphaFMtVGozUUJKOC1yLThILVZkQVNBY2x3Tzh4WUNjcnpzUEhpb2lpbyIsImtSSzRWcHZFNThaQTdDTWhpaW85VGlESXd6QW9YMkhWVi0tNXFJU2t0Z2siLCJ2VjFNVEdIQmZqUnRadzZuXzM2WXU0QkZUYWNENnl5TVVSUC0wSk1JdWswIl19fQ.jFKrh_m-fWbx9sFg30zPeSIfjid4u8QdFY9KH9qIL1eW33QdNgOasVEnMFozTKMbMLNtke8eQq6jD2yEN8NEwQ~WyJiMTIxMzEzZjNhNjQ5OTQ0NDlhZmM0NTEzMjIwNDkyYyIsImZhbWlseV9uYW1lIiwiRkVSUkVJUkEgREEgU0lMVkEiXQ~WyIyZjE0NmI1YjBmOGYyMzYwNjA4ZDJjNDA4MzVjMjM5OCIsImdpdmVuX25hbWUiLCJKT1JHRSBFTUFOVUVMIl0~eyJ0eXAiOiJrYitqd3QiLCJhbGciOiJFUzI1NiJ9.eyJpYXQiOjE3NzIwOTc1MDYsIm5iZiI6MTc3MjA5NzUwNiwiZXhwIjoxNzc5OTg2NzM4LCJhdWQiOiJ4NTA5X3Nhbl9kbnM6aHR0cHM6Ly9kc3dhbGxldG9pZGMtZGV2LmRpZ2l0YWxzaWduLnB0L2RpZ2l0YWxzaWduIiwibm9uY2UiOiJiMmFmYTc4YmQwZjM5NGNmYjAzOWIxYjUzNzAxYmI2NCIsInNkX2hhc2giOiJvTm1zUGpHSW9NTFI4YVdhYnFuY0Q2TVU1bWFnMUl2d0YxVjlyelB5bmc0In0.571trHo9G_stwokju-AK2pluL3LtcOoG1ECX4DFSqwvy2fc54Tsd2X7kRSe5_wAXWeo6uvJTebMqDS9eEoADaA".getBytes());
    }

    @Override
    protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
        SignedDocumentValidator validator = super.getValidator(signedDocument);
        validator.setCertificateVerifier(getOfflineCertificateVerifier());
        return validator;
    }

    @Override
    protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
        boolean eaaSignatureFound = false;
        boolean keyBindingSignatureFound = false;
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            if (signatureWrapper.getSigningCertificate() != null) {
                eaaSignatureFound = true;
            } else if (signatureWrapper.getSigningCertificatePublicKey() != null) {
                keyBindingSignatureFound = true;
            }
        }
        assertTrue(eaaSignatureFound);
        assertTrue(keyBindingSignatureFound);
    }

    @Override
    protected void checkSigningDate(DiagnosticData diagnosticData) {
        // not present
    }

    @Override
    protected void checkStructureValidation(DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected void validateSignerInformation(SignerInformationType signerInformation) {
        // skip
    }

    @Override
    protected boolean orphanSelectivelyDisclosableClaimsPresent() {
        return true;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
