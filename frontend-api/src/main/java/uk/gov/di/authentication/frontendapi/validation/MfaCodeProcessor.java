package uk.gov.di.authentication.frontendapi.validation;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.shared.domain.AuditableEvent;
import uk.gov.di.authentication.shared.entity.CountType;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationAttemptsService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoAccountModifiersService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Optional;

import static uk.gov.di.audit.AuditContext.auditContextFromUserContext;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;

public abstract class MfaCodeProcessor {
    protected final Logger LOG = LogManager.getLogger(this.getClass());
    public final CodeStorageService codeStorageService;
    public final DynamoAccountModifiersService accountModifiersService;
    private final int maxRetries;
    public final String emailAddress;
    private final UserContext userContext;
    protected final AuthenticationService dynamoService;
    protected final AuditService auditService;
    protected final AuthenticationAttemptsService authenticationAttemptsService;
    protected final ConfigurationService configurationService;

    MfaCodeProcessor(
            UserContext userContext,
            CodeStorageService codeStorageService,
            int maxRetries,
            AuthenticationService dynamoService,
            AuditService auditService,
            DynamoAccountModifiersService accountModifiersService,
            AuthenticationAttemptsService authenticationAttemptsService,
            ConfigurationService configurationService) {
        this.emailAddress = userContext.getAuthSession().getEmailAddress();
        this.userContext = userContext;
        this.codeStorageService = codeStorageService;
        this.maxRetries = maxRetries;
        this.dynamoService = dynamoService;
        this.auditService = auditService;
        this.accountModifiersService = accountModifiersService;
        this.authenticationAttemptsService = authenticationAttemptsService;
        this.configurationService = configurationService;
    }

    boolean isCodeBlockedForSession(String codeBlockedKeyPrefix) {
        return codeStorageService.isBlockedForEmail(emailAddress, codeBlockedKeyPrefix);
    }

    boolean hasExceededRetryLimit(MFAMethodType mfaMethodType, JourneyType journeyType) {
        LOG.info("Max retries: {}", maxRetries);
        return authenticationAttemptsService.getCount(
                        userContext.getAuthSession().getInternalCommonSubjectId(),
                        journeyType,
                        mfaMethodType.equals(MFAMethodType.AUTH_APP)
                                ? CountType.ENTER_AUTH_APP_CODE
                                : CountType.ENTER_SMS_CODE)
                >= maxRetries;
    }

    void incrementRetryCount(MFAMethodType mfaMethodType, JourneyType journeyType) {
        authenticationAttemptsService.createOrIncrementCount(
                userContext.getAuthSession().getInternalCommonSubjectId(),
                configurationService.getLockoutCountTTL(),
                journeyType,
                mfaMethodType.equals(MFAMethodType.AUTH_APP)
                        ? CountType.ENTER_AUTH_APP_CODE
                        : CountType.ENTER_SMS_CODE);
    }

    void resetCodeIncorrectEntryCount(MFAMethodType mfaMethodType, JourneyType journeyType) {
        authenticationAttemptsService.deleteCount(
                userContext.getAuthSession().getInternalCommonSubjectId(),
                journeyType,
                mfaMethodType.equals(MFAMethodType.AUTH_APP)
                        ? CountType.ENTER_AUTH_APP_CODE
                        : CountType.ENTER_SMS_CODE);
    }

    void submitAuditEvent(
            AuditableEvent auditableEvent,
            MFAMethodType mfaMethodType,
            String phoneNumber,
            String ipAddress,
            String persistentSessionId,
            boolean accountRecovery) {

        var auditContext =
                auditContextFromUserContext(
                        userContext,
                        userContext.getAuthSession().getInternalCommonSubjectId(),
                        emailAddress,
                        ipAddress,
                        phoneNumber,
                        persistentSessionId);

        auditService.submitAuditEvent(
                auditableEvent,
                auditContext,
                pair("mfa-type", mfaMethodType.getValue()),
                pair("account-recovery", accountRecovery));
    }

    void clearAccountRecoveryBlockIfPresent(
            MFAMethodType mfaMethodType, String ipAddress, String persistentSessionId) {
        var accountRecoveryBlockPresent =
                accountModifiersService.isAccountRecoveryBlockPresent(
                        userContext.getAuthSession().getInternalCommonSubjectId());
        if (accountRecoveryBlockPresent) {
            LOG.info("AccountRecovery block is present. Removing block");
            accountModifiersService.removeAccountRecoveryBlockIfPresent(
                    userContext.getAuthSession().getInternalCommonSubjectId());
            var auditContext =
                    auditContextFromUserContext(
                            userContext,
                            userContext.getAuthSession().getInternalCommonSubjectId(),
                            emailAddress,
                            ipAddress,
                            AuditService.UNKNOWN,
                            persistentSessionId);
            auditService.submitAuditEvent(
                    FrontendAuditableEvent.AUTH_ACCOUNT_RECOVERY_BLOCK_REMOVED,
                    auditContext,
                    pair("mfa-type", mfaMethodType.getValue()));
        }
    }

    public abstract Optional<ErrorResponse> validateCode();

    public abstract void processSuccessfulCodeRequest(String ipAddress, String persistentSessionId);
}
