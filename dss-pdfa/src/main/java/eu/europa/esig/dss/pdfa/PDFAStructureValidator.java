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
package eu.europa.esig.dss.pdfa;

import eu.europa.esig.dss.model.DSSDocument;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.verapdf.gf.foundry.VeraGreenfieldFoundryProvider;
import org.verapdf.pdfa.Foundries;
import org.verapdf.pdfa.PDFAParser;
import org.verapdf.pdfa.PDFAValidator;
import org.verapdf.pdfa.VeraPDFFoundry;
import org.verapdf.pdfa.flavours.PDFAFlavour;
import org.verapdf.pdfa.results.TestAssertion;
import org.verapdf.pdfa.results.ValidationResult;

import java.io.InputStream;
import java.util.Collection;
import java.util.stream.Collectors;

/**
 * Util class used for a PDF validation against a PDF/A specification
 *
 */
public class PDFAStructureValidator {

    private static final Logger LOG = LoggerFactory.getLogger(PDFAStructureValidator.class);

    /** Used to create PDF Parser and Validator */
    private static final VeraPDFFoundry FOUNDRY;

    static {
        VeraGreenfieldFoundryProvider.initialise();
        FOUNDRY = Foundries.defaultInstance();
    }

    /**
     * Default constructor
     */
    public PDFAStructureValidator() {
        // empty
    }

    /**
     * This method validates a PDF/A structure for the given PDF document
     *
     * @param signedDocument PDF {@link DSSDocument} to be validated
     * @return TRUE if the PDF is a valid PDF/A document, FALSE otherwise
     */
    public PDFAValidationResult validate(DSSDocument signedDocument) {
        try (InputStream is = signedDocument.openStream(); PDFAParser parser = FOUNDRY.createParser(is);
             PDFAValidator validator = FOUNDRY.createValidator(parser.getFlavour(), false)) {

            ValidationResult result = validator.validate(parser);
            return toPDFAValidationResult(result);

        } catch (Exception e) {
            LOG.error("Unable to perform PDF/A structure validation. Reason : {}", e.getMessage(), e);
            return null;
        }
    }

    private PDFAValidationResult toPDFAValidationResult(ValidationResult validationResult) {
        PDFAValidationResult pdfaValidationResult = new PDFAValidationResult();
        pdfaValidationResult.setProfileId(buildProfileId(validationResult));
        pdfaValidationResult.setCompliant(validationResult.isCompliant());
        pdfaValidationResult.setErrorMessages(getErrorMessages(validationResult));
        return pdfaValidationResult;
    }

    private String buildProfileId(ValidationResult validationResult) {
        PDFAFlavour pdfaFlavour = validationResult.getPDFAFlavour();
        PDFAFlavour.Specification part = pdfaFlavour.getPart();
        PDFAFlavour.SpecificationFamily family = part.getFamily();
        PDFAFlavour.Level level = pdfaFlavour.getLevel();
        return String.format("%s-%s%s", family.getFamily(), part.getPartNumber(), level);
    }

    private Collection<String> getErrorMessages(ValidationResult validationResult) {
        return validationResult.getTestAssertions().stream().filter(a -> TestAssertion.Status.FAILED == a.getStatus())
                .map(a -> normalize(a.getMessage())).collect(Collectors.toSet());
    }

    private String normalize(String str) {
        return str.trim().replace("\n", " ").replace("\t", " ")
                .replace(" +", " ");
    }

}
