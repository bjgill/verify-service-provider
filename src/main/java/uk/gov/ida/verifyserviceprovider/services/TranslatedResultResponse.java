package uk.gov.ida.verifyserviceprovider.services;

import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.StatusCode;
import uk.gov.ida.verifyserviceprovider.dto.LevelOfAssurance;
import uk.gov.ida.verifyserviceprovider.dto.TranslatedResponseBody;

import java.util.List;

interface TranslatedResultResponse {

    TranslatedResponseBody translateNonSuccessResponse( StatusCode statusCode );

    TranslatedResponseBody translateSuccessResponse( List<Assertion> assertions,
                                                     String expectedInResponseTo,
                                                     LevelOfAssurance expectedLevelOfAssurance,
                                                     String entityId );
}
