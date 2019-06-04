/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.user.store.outbound;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.user.store.common.MessageRequestUtil;
import org.wso2.carbon.identity.user.store.common.UserStoreConstants;
import org.wso2.carbon.identity.user.store.common.messaging.JMSConnectionException;
import org.wso2.carbon.identity.user.store.common.messaging.JMSConnectionFactory;
import org.wso2.carbon.identity.user.store.common.model.UserOperation;
import org.wso2.carbon.identity.user.store.outbound.cache.*;
import org.wso2.carbon.user.api.ClaimMapping;
import org.wso2.carbon.user.api.Properties;
import org.wso2.carbon.user.api.Property;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreConfigConstants;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.claim.ClaimManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.RoleContext;
import org.wso2.carbon.user.core.profile.ProfileConfigurationManager;
import org.wso2.carbon.user.core.tenant.Tenant;
import org.wso2.carbon.user.core.util.DatabaseUtil;
import org.wso2.carbon.user.core.util.JDBCRealmUtil;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.Secret;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import javax.jms.Connection;
import javax.jms.DeliveryMode;
import javax.jms.Destination;
import javax.jms.JMSException;
import javax.jms.Message;
import javax.jms.MessageConsumer;
import javax.jms.MessageProducer;
import javax.jms.ObjectMessage;
import javax.jms.Session;

/**
 * Outbound Agent User store manager
 */
public class WSOutboundUserStoreManager extends AbstractUserStoreManager {

    private static Log LOGGER = LogFactory.getLog(WSOutboundUserStoreManager.class);
    private static String JMS_CORRELATIONID_FILTER = "JMSCorrelationID='%s'";

    private final String SHA_256 = "SHA-256";

    public WSOutboundUserStoreManager() {

    }

    /**
     * @param realmConfig Realm configuration
     * @param tenantId Tenant Id
     * @throws UserStoreException
     */
    public WSOutboundUserStoreManager(RealmConfiguration realmConfig, int tenantId) throws UserStoreException {
        this.realmConfig = realmConfig;
        this.tenantId = tenantId;

        if (realmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.READ_GROUPS_ENABLED) != null) {
            readGroupsEnabled = Boolean.parseBoolean(realmConfig
                    .getUserStoreProperty(UserCoreConstants.RealmConfig.READ_GROUPS_ENABLED));
        }

        if (LOGGER.isDebugEnabled()) {
            if (readGroupsEnabled) {
                LOGGER.debug("ReadGroups is enabled for " + getMyDomainName());
            } else {
                LOGGER.debug("ReadGroups is disabled for " + getMyDomainName());
            }
        }

        if (realmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.WRITE_GROUPS_ENABLED) != null) {
            writeGroupsEnabled = Boolean.parseBoolean(realmConfig
                    .getUserStoreProperty(UserCoreConstants.RealmConfig.WRITE_GROUPS_ENABLED));
        } else {
            if (!isReadOnly()) {
                writeGroupsEnabled = true;
            }
        }

        if (LOGGER.isDebugEnabled()) {
            if (writeGroupsEnabled) {
                LOGGER.debug("WriteGroups is enabled for " + getMyDomainName());
            } else {
                LOGGER.debug("WriteGroups is disabled for " + getMyDomainName());
            }
        }

        if (writeGroupsEnabled) {
            readGroupsEnabled = true;
        }

	/* Initialize user roles cache as implemented in AbstractUserStoreManager */
        initUserRolesCache();
    }

    public WSOutboundUserStoreManager(org.wso2.carbon.user.api.RealmConfiguration realmConfig,
            Map<String, Object> properties,
            ClaimManager claimManager,
            ProfileConfigurationManager profileManager,
            UserRealm realm, Integer tenantId)
            throws UserStoreException {

        this(realmConfig, tenantId);
        this.realmConfig = realmConfig;
        this.tenantId = tenantId;
        this.userRealm = realm;

        this.claimManager = claimManager;
        this.userRealm = realm;

        dataSource = (org.apache.tomcat.jdbc.pool.DataSource) properties.get(UserCoreConstants.DATA_SOURCE);
        if (dataSource == null) {
            dataSource = DatabaseUtil.getRealmDataSource(realmConfig);
        }
        if (dataSource == null) {
            throw new UserStoreException("User Management Data Source is null");
        }

        properties.put(UserCoreConstants.DATA_SOURCE, dataSource);
        realmConfig.setUserStoreProperties(JDBCRealmUtil.getSQL(realmConfig.getUserStoreProperties()));

        this.persistDomain();
        doInitialSetup();
        if (realmConfig.isPrimary()) {
            addInitialAdminData(Boolean.parseBoolean(realmConfig.getAddAdmin()),
                    !isInitSetupDone());
        }

        initUserRolesCache();
    }

    @Override
    public boolean doAuthenticate(String userName, Object credential) throws UserStoreException {
        Date startDate = new Date();
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Processing authentication request for tenantId  - [" + this.tenantId + "]");
        }

        if (userName != null && credential != null) {
            Secret secret = (Secret) credential;
            String identifier;
            try {
                identifier = getSha256SecuredIdentifier(String.copyValueOf(secret.getChars()));
            } catch (NoSuchAlgorithmException e) {
                LOGGER.error("Error occurred while generating identifier.", e);
                return false;
            }
            UserAuthCacheKey userAuthCacheKey = new UserAuthCacheKey(userName);
            UserAuthCacheEntry userAuthCacheEntry = UserAuthCache.getInstance().getValueFromCache(userAuthCacheKey);

            if (userAuthCacheEntry != null) {
                if (identifier.equals(userAuthCacheEntry.getUserIdentifier())) {
                    if (LOGGER.isDebugEnabled()) {
                        LOGGER.debug("Cache hit for user : " + userName + ". Authentication completed in "
                                + (new Date().getTime() - startDate.getTime()) + "ms.");
                    }
                    return true;
                } else {
                    UserAuthCache.getInstance().clearCacheEntry(userAuthCacheKey);
                }
            }

            boolean isAuthenticated = processAuthenticationRequest(userName, credential);
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Authentication the user:" + userName + " completed with result:"
                        + isAuthenticated + " in " + (new Date().getTime() - startDate.getTime()) + "ms.");
            }
            if (isAuthenticated) {
                String lockedString = userName + "@WSOutboundUserStoreManager_doAuthenticate";
                synchronized (lockedString.intern()) {
                    if (UserAuthCache.getInstance().getValueFromCache(userAuthCacheKey) == null) {
                        UserAuthCache.getInstance().addToCache(userAuthCacheKey, new UserAuthCacheEntry(identifier));
                    }
                }
            }

            return isAuthenticated;
        }
        return false;
    }

    private String getSha256SecuredIdentifier(String originalIdentifier) throws NoSuchAlgorithmException {
        String sha256Identifier;
        MessageDigest md = MessageDigest.getInstance(SHA_256);
        md.update(originalIdentifier.getBytes());
        byte[] hashInBytes = md.digest();
        StringBuilder sb = new StringBuilder();
        for (byte b : hashInBytes) {
            sb.append(String.format("%02x", b));
        }
        sha256Identifier = sb.toString();
        return sha256Identifier;
    }

    private boolean processAuthenticationRequest(String userName, Object credential) {
        Date startDate = new Date();
        JMSConnectionFactory connectionFactory = new JMSConnectionFactory();
        Connection connection = null;
        Session requestSession;
        Session responseSession;
        Destination requestTopic;
        Destination responseQueue;
        MessageProducer producer;

        try {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Sending authentication request to queue for tenant  - [" + this.tenantId + "]");
            }
            connectionFactory.createActiveMQConnectionFactory(getMessageBrokerURL());
            connection = connectionFactory.createConnection();
            connectionFactory.start(connection);
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("JMS connection created in " + (new Date().getTime() - startDate.getTime()) + "ms.");
            }
            requestSession = connectionFactory.createSession(connection);
            requestTopic = connectionFactory
                    .createTopicDestination(requestSession, UserStoreConstants.TOPIC_NAME_REQUEST);
            producer = connectionFactory
                    .createMessageProducer(requestSession, requestTopic, DeliveryMode.NON_PERSISTENT);
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("JMS connection and producer created in " +
                        (new Date().getTime() - startDate.getTime()) + "ms.");
            }
            Message responseMessage = null;
            int retryCount = 0;
            while (responseMessage == null && getMessageRetryLimit() > retryCount) {

                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("Trying to authenticate user: " + userName + " count: " + retryCount);
                }
                String correlationId = UUID.randomUUID().toString();
                responseQueue = connectionFactory
                        .createQueueDestination(requestSession, UserStoreConstants.QUEUE_NAME_RESPONSE);
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("JMS connection,producer and destination queue created in "
                            + (new Date().getTime() - startDate.getTime()) + "ms.");
                }
                addNextUserOperationToTopic(correlationId, UserStoreConstants.UM_OPERATION_TYPE_AUTHENTICATE,
                        MessageRequestUtil.getAuthenticationRequest(userName, credential), requestSession, producer,
                        responseQueue);
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("Authentication request published to tpoic in " +
                            (new Date().getTime() - startDate.getTime()) + "ms.");
                }
                responseSession = connectionFactory.createSession(connection);

                String filter = String.format(JMS_CORRELATIONID_FILTER, correlationId);
                MessageConsumer consumer = responseSession.createConsumer(responseQueue, filter);
                Date startReceiveTime = new Date();
                responseMessage = consumer.receive(getMessageConsumeTimeout());
                retryCount++;
                if (LOGGER.isDebugEnabled() && responseMessage != null) {
                    LOGGER.debug("Received response for user operation : " + UserStoreConstants
                            .UM_OPERATION_TYPE_AUTHENTICATE + " correlationId : " + correlationId + " tenant id " +
                            ": " + tenantId + " in " + (new Date().getTime() - startReceiveTime.getTime()) + "ms.");
                }
            }

            if (responseMessage != null) {
                UserOperation response = (UserOperation) ((ObjectMessage) responseMessage).getObject();
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug(
                            "Authentication response: " + response.getResponseData() + " for user: " + userName);
                }
                JSONObject jsonResult = new JSONObject(response.getResponseData());
                return UserStoreConstants.UM_OPERATION_AUTHENTICATE_RESULT_SUCCESS
                        .equals(jsonResult.get(UserStoreConstants.UM_JSON_ELEMENT_RESPONSE_DATA_RESULT).toString());
            } else {
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("Authentication failed for user: " + userName + " due to response object is null");
                }
                return false;
            }
        } catch (JMSConnectionException e) {
            LOGGER.error("Error occurred while creating JMS connection", e);
        } catch (JMSException e) {
            LOGGER.error("Error occurred while adding message to queue", e);
        } catch (JSONException e) {
            LOGGER.error("Error occurred transforming json message response", e);
        } finally {
            try {
                connectionFactory.closeConnection(connection);
            } catch (JMSConnectionException e) {
                LOGGER.error("Error occurred while closing the connection", e);
            }
        }
        return false;
    }

    /**
     * Add next user operation to queue
     * @param correlationId Connection Id
     * @param operationType Operation type ex. authenticate, getuserlist etc.
     * @param requestData Request data ex. username/password
     * @param requestSession JMS session
     * @param producer JMS Producer
     * @param responseQueue Destination queue to add the message
     * @throws JMSException
     */
    private void addNextUserOperationToTopic(String correlationId, String operationType, String requestData,
            Session requestSession, MessageProducer producer, Destination responseQueue)
            throws JMSException {

        String tenantDomain = IdentityTenantUtil.getTenantDomain(tenantId);

        UserOperation requestOperation = new UserOperation();
        requestOperation.setCorrelationId(correlationId);
        requestOperation.setRequestData(requestData);
        requestOperation.setTenant(tenantDomain);
        requestOperation.setRequestType(operationType);
        requestOperation.setDomain(realmConfig.getUserStoreProperty(UserStoreConfigConstants.DOMAIN_NAME));

        ObjectMessage requestMessage = requestSession.createObjectMessage();
        requestMessage.setObject(requestOperation);
        requestMessage.setJMSCorrelationID(correlationId);
        requestMessage.setJMSExpiration(getMessageLifeTime());
        requestMessage.setJMSReplyTo(responseQueue);

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Sending user operation : " + operationType + " with correlationId : " + correlationId +
                    " tenant domain : " + tenantDomain);
        }

        producer.send(requestMessage);
    }

    @Override
    protected void doAddUser(String userName, Object credential, String[] roleList, Map<String, String> claims,
            String profileName, boolean requirePasswordChange) throws UserStoreException {
        throw new UserStoreException("UserStoreManager method not supported : #doAddUser");

    }

    @Override
    protected void doUpdateCredential(String userName, Object newCredential, Object oldCredential)
            throws UserStoreException {
        throw new UserStoreException("UserStoreManager method not supported : #doUpdateCredential");

    }

    @Override
    protected void doUpdateCredentialByAdmin(String userName, Object newCredential) throws UserStoreException {
        throw new UserStoreException("UserStoreManager method not supported : #doUpdateCredentialByAdmin");

    }

    @Override
    protected void doDeleteUser(String userName) throws UserStoreException {
        throw new UserStoreException("UserStoreManager method not supported : #doDeleteUser");

    }

    @Override
    protected void doSetUserClaimValue(String userName, String claimURI, String claimValue, String profileName)
            throws UserStoreException {
        throw new UserStoreException("UserStoreManager method not supported : #doSetUserClaimValue");

    }

    @Override
    protected void doSetUserClaimValues(String userName, Map<String, String> claims, String profileName)
            throws UserStoreException {
        throw new UserStoreException("UserStoreManager method not supported : #doSetUserClaimValues");

    }

    @Override
    protected void doDeleteUserClaimValue(String userName, String claimURI, String profileName)
            throws UserStoreException {
        throw new UserStoreException("UserStoreManager method not supported : #doDeleteUserClaimValue");

    }

    @Override
    protected void doDeleteUserClaimValues(String userName, String[] claims, String profileName)
            throws UserStoreException {
        throw new UserStoreException("UserStoreManager method not supported : #doDeleteUserClaimValues");

    }

    @Override
    protected void doUpdateUserListOfRole(String roleName, String[] deletedUsers, String[] newUsers)
            throws UserStoreException {
        throw new UserStoreException("UserStoreManager method not supported : #doUpdateUserListOfRole");

    }

    @Override
    protected void doUpdateRoleListOfUser(String userName, String[] deletedRoles, String[] newRoles)
            throws UserStoreException {
        throw new UserStoreException("UserStoreManager method not supported : #doUpdateRoleListOfUser");

    }

    private String getAllClaimMapAttributes(ClaimMapping[] claimMappings) {

        StringBuilder queryBuilder = new StringBuilder();
        String myDomainName = getMyDomainName();

        for (ClaimMapping mapping : claimMappings) {
            if (mapping.getMappedAttribute(myDomainName) != null) {
                queryBuilder.append(",").append(mapping.getMappedAttribute(myDomainName));
            }
        }
        String attributeList = queryBuilder.toString().replaceFirst(",", "");
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Requested Attributes list: " + attributeList);
        }
        return attributeList;
    }

    public Map<String, String> getUserPropertyValues(String userName, String[] propertyNames, String profileName)
            throws UserStoreException {

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Sending get user properties of user: " + userName + " for tenant  - [" + this.tenantId + "]");
        }

        UserAttributeCacheEntry cacheEntry = getUserAttributesFromCache(userName);
        Map<String, String> allUserAttributes = new HashMap<>();
        Map<String, String> mapAttributes = new HashMap<>();
        if (cacheEntry == null) {

            JMSConnectionFactory connectionFactory = new JMSConnectionFactory();
            Connection connection = null;
            Session requestSession;
            Session responseSession;
            Destination requestTopic;
            Destination responseQueue;
            MessageProducer producer;
            try {
                connectionFactory.createActiveMQConnectionFactory(getMessageBrokerURL());
                connection = connectionFactory.createConnection();
                connectionFactory.start(connection);
                requestSession = connectionFactory.createSession(connection);
                requestTopic = connectionFactory
                        .createTopicDestination(requestSession, UserStoreConstants.TOPIC_NAME_REQUEST);
                producer = connectionFactory
                        .createMessageProducer(requestSession, requestTopic, DeliveryMode.NON_PERSISTENT);

                int retryCount = 0;
                Message responseMessage = null;

                while (responseMessage == null && getMessageRetryLimit() > retryCount) {
                    if (LOGGER.isDebugEnabled()) {
                        LOGGER.debug("Trying to get user properties [" + Arrays.toString(propertyNames) +  "]" +
                                "  for user: " + userName + " count: " + retryCount);
                    }
                    String correlationId = UUID.randomUUID().toString();
                    responseQueue = connectionFactory
                            .createQueueDestination(requestSession, UserStoreConstants.QUEUE_NAME_RESPONSE);

                    addNextUserOperationToTopic(correlationId, UserStoreConstants.UM_OPERATION_TYPE_GET_CLAIMS,
                            MessageRequestUtil.getUserPropertyValuesRequestData(userName, getAllClaimMapAttributes(
                                    claimManager.getAllClaimMappings())),
                            requestSession, producer, responseQueue);

                    responseSession = connectionFactory.createSession(connection);

                    String filter = String.format(JMS_CORRELATIONID_FILTER, correlationId);
                    MessageConsumer consumer = responseSession.createConsumer(responseQueue, filter);
                    responseMessage = consumer.receive(getMessageConsumeTimeout());

                    if(responseMessage != null) {
                        if (LOGGER.isDebugEnabled()) {
                            LOGGER.debug("Received response for user operation : " + UserStoreConstants
                                    .UM_OPERATION_TYPE_GET_CLAIMS + " correlationId : " + correlationId + " tenant id" +
                                    " : " + tenantId);
                        }
                        UserOperation response = (UserOperation) ((ObjectMessage) responseMessage).getObject();
                        JSONObject responseObj = new JSONObject(response.getResponseData());
                        JSONObject resultObj = new JSONObject(
                                responseObj.get(UserStoreConstants.UM_JSON_ELEMENT_RESPONSE_DATA_RESULT).toString());
                        Iterator iterator = resultObj.keys();
                        while (iterator.hasNext()) {
                            String key = (String) iterator.next();
                            allUserAttributes.put(key, (String) resultObj.get(key));
                        }
                        addAttributesToCache(userName, allUserAttributes);
                    } else {
                        if (LOGGER.isDebugEnabled()) {
                            LOGGER.debug("Response is null for get user properties user: " + userName + " count: "
                                    + retryCount);
                        }
                    }
                    retryCount++;
                }

            } catch (JMSConnectionException e) {
                LOGGER.error("Error occurred while creating JMS connection", e);
            } catch (JMSException e) {
                LOGGER.error("Error occurred while adding message to queue", e);
            } catch (org.wso2.carbon.user.api.UserStoreException e) {
                LOGGER.error("Error occurred while getting claim mappings", e);
            } catch (JSONException e) {
                LOGGER.error("Error occurred while reading JSON object", e);
            } finally {
                try {
                    connectionFactory.closeConnection(connection);
                } catch (JMSConnectionException e) {
                    LOGGER.error("Error occurred while closing the connection", e);
                }
            }

        } else {
            allUserAttributes = cacheEntry.getUserAttributes();
        }
        for (String propertyName : propertyNames) {
            mapAttributes.put(propertyName, allUserAttributes.get(propertyName));
        }
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Get user properties completed. User: " + userName + " attributes: " +
                    mapAttributes.toString());
        }
        return mapAttributes;
    }

    private void addAttributesToCache(String userName, Map<String, String> attributes) {

        UserAttributeCacheKey cacheKey = new UserAttributeCacheKey(userName);
        UserAttributeCacheEntry cacheEntry = new UserAttributeCacheEntry();
        cacheEntry.setUserAttributes(attributes);
        UserAttributeCache.getInstance().addToCache(cacheKey, cacheEntry);
    }

    private UserAttributeCacheEntry getUserAttributesFromCache(String userName) {

        UserAttributeCacheKey cacheKey = new UserAttributeCacheKey(userName);
        return UserAttributeCache.getInstance().getValueFromCache(cacheKey);
    }

    //Todo: Implement doCheckExistingRole
    @Override
    protected boolean doCheckExistingRole(String roleName) throws UserStoreException {
        return true;
    }

    @Override
    protected RoleContext createRoleContext(String roleName) throws UserStoreException {
        throw new UserStoreException("UserStoreManager method not supported : #createRoleContext");
    }

    //Todo: Implement doCheckExistingUser
    @Override
    protected boolean doCheckExistingUser(String userName) throws UserStoreException {
        return true;
    }

    @Override
    protected String[] getUserListFromProperties(String property, String value, String profileName)
            throws UserStoreException {
        throw new UserStoreException("UserStoreManager method not supported : #getUserListFromProperties");
    }

    @Override
    public String[] getProfileNames(String userName) throws UserStoreException {
        throw new UserStoreException("UserStoreManager method not supported : #getProfileNames");
    }

    @Override
    public String[] getAllProfileNames() throws UserStoreException {
        throw new UserStoreException("UserStoreManager method not supported : #getAllProfileNames");
    }

    @Override
    public boolean isReadOnly() throws UserStoreException {
        return "true".equalsIgnoreCase(realmConfig
                .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_READ_ONLY));
    }

    public Date getPasswordExpirationTime(String userName) throws UserStoreException {
        return super.getPasswordExpirationTime(userName);
    }

    @Override
    public int getUserId(String username) throws UserStoreException {
        throw new UserStoreException("UserStoreManager method not supported : #getUserId");
    }

    @Override
    public int getTenantId(String username) throws UserStoreException {
        throw new UserStoreException("UserStoreManager method not supported : #getTenantId");
    }

    @Override
    public int getTenantId() throws UserStoreException {
        return this.tenantId;
    }

    @Override
    public Map<String, String> getProperties(org.wso2.carbon.user.api.Tenant tenant) throws UserStoreException {
        throw new UserStoreException("UserStoreManager method not supported : #getProperties");
    }

    @Override
    public boolean isMultipleProfilesAllowed() {
        return false;
    }

    @Override
    public void addRememberMe(String s, String s1) throws org.wso2.carbon.user.api.UserStoreException {
        throw new UserStoreException("UserStoreManager method not supported : #addRememberMe");

    }

    @Override
    public boolean isValidRememberMeToken(String s, String s1) throws org.wso2.carbon.user.api.UserStoreException {
        throw new UserStoreException("UserStoreManager method not supported : #isValidRememberMeToken");
    }

    @Override
    public Map<String, String> getProperties(Tenant tenant) throws UserStoreException {
        throw new UserStoreException("UserStoreManager method not supported : #getProperties");
    }

    @Override
    public boolean isBulkImportSupported() {
        return Boolean.valueOf(this.realmConfig.getUserStoreProperty("IsBulkImportSupported"));
    }

    private String getMessageBrokerURL() {
        return this.realmConfig
                .getUserStoreProperty(UserStoreConstants.USER_STORE_PROPERTY_NAME_MESSAGE_BROKER_ENDPOINT);
    }

    private int getMessageRetryLimit() {
        return Integer.parseInt(
                this.realmConfig.getUserStoreProperty(UserStoreConstants.USER_STORE_PROPERTY_NAME_MESSAGE_RETRY_LIMIT));
    }

    private int getMessageLifeTime() {
        return Integer.parseInt(
                this.realmConfig.getUserStoreProperty(UserStoreConstants.USER_STORE_PROPERTY_NAME_MESSAGE_LIFETIME));
    }

    private int getMessageConsumeTimeout() {
        return Integer.parseInt(
                this.realmConfig
                        .getUserStoreProperty(UserStoreConstants.USER_STORE_PROPERTY_NAME_MESSAGE_CONSUME_TIMEOUT));
    }

    public Properties getDefaultUserStoreProperties() {

        Properties properties = new Properties();
        Property brokerUrl = new Property(UserStoreConstants.USER_STORE_PROPERTY_NAME_MESSAGE_BROKER_ENDPOINT, "",
                "Message Broker connection URL", null);
        Property messageConsumeTimeout = new Property(
                UserStoreConstants.USER_STORE_PROPERTY_NAME_MESSAGE_CONSUME_TIMEOUT, "", "Message consume timeout",
                null);
        Property messageLifetime = new Property(UserStoreConstants.USER_STORE_PROPERTY_NAME_MESSAGE_LIFETIME, "",
                "Message lifetime", null);
        Property messageRetryLimit = new Property(UserStoreConstants.USER_STORE_PROPERTY_NAME_MESSAGE_RETRY_LIMIT, "",
                "Message retry limit", null);

        Property disabled = new Property("Disabled", "false", "Disabled#Check to disable the user store", null);

        Property[] mandatoryProperties = new Property[] { brokerUrl, messageConsumeTimeout, messageLifetime,
                messageRetryLimit };
        Property[] optionalProperties = new Property[] { disabled };

        properties.setOptionalProperties(optionalProperties);
        properties.setMandatoryProperties(mandatoryProperties);
        return properties;
    }

    @Override
    public RealmConfiguration getRealmConfiguration() {
        return this.realmConfig;
    }

    @Override
    protected String[] doGetSharedRoleNames(String tenantDomain, String filter, int maxItemLimit)
            throws UserStoreException {
        throw new UserStoreException("UserStoreManager method not supported : #doGetSharedRoleNames");
    }

    //Todo: Implement doGetUserListOfRole
    @Override
    protected String[] doGetUserListOfRole(String roleName, String filter) throws UserStoreException {
        return null;
    }

    public String[] doListUsers(String filter, int maxItemLimit) throws UserStoreException {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Processing doListUsers request for tenantId  - [" + this.tenantId + "]");
        }

        JMSConnectionFactory connectionFactory = new JMSConnectionFactory();
        Connection connection = null;
        Session requestSession;
        Session responseSession;
        Destination requestTopic;
        Destination responseQueue;
        MessageProducer producer;
        List<String> userList = new ArrayList<>();
        try {
            connectionFactory.createActiveMQConnectionFactory(getMessageBrokerURL());
            connection = connectionFactory.createConnection();
            connectionFactory.start(connection);
            requestSession = connectionFactory.createSession(connection);
            requestTopic = connectionFactory
                    .createTopicDestination(requestSession, UserStoreConstants.TOPIC_NAME_REQUEST);
            producer = connectionFactory
                    .createMessageProducer(requestSession, requestTopic, DeliveryMode.NON_PERSISTENT);

            int retryCount = 0;
            Message responseMessage = null;

            while (responseMessage == null && getMessageRetryLimit() > retryCount) {
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("Trying to get user list count: " + retryCount);
                }
                String correlationId = UUID.randomUUID().toString();
                responseQueue = connectionFactory
                        .createQueueDestination(requestSession, UserStoreConstants.QUEUE_NAME_RESPONSE);

                addNextUserOperationToTopic(correlationId, UserStoreConstants.UM_OPERATION_TYPE_GET_USER_LIST,
                        MessageRequestUtil.getUserListRequest(
                                filter, maxItemLimit), requestSession, producer, responseQueue);

                responseSession = connectionFactory.createSession(connection);

                String selector = String.format(JMS_CORRELATIONID_FILTER, correlationId);
                MessageConsumer consumer = responseSession.createConsumer(responseQueue, selector);
                responseMessage = consumer.receive(getMessageConsumeTimeout());
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("Received response for user operation : " + UserStoreConstants
                            .UM_OPERATION_TYPE_GET_USER_LIST + " correlationId : " + correlationId + " tenant id " +
                            ": " + tenantId);
                }
                if(responseMessage != null) {
                    UserOperation response = (UserOperation) ((ObjectMessage) responseMessage).getObject();
                    JSONObject responseObj = new JSONObject(response.getResponseData());
                    JSONObject resultObj = new JSONObject(
                            responseObj.get(UserStoreConstants.UM_JSON_ELEMENT_RESPONSE_DATA_RESULT).toString());
                    JSONArray users = resultObj.getJSONArray("usernames");
                    for (int i = 0; i < users.length(); i++) {
                        String user = (String) users.get(i);
                        if (!CarbonConstants.REGISTRY_ANONNYMOUS_USERNAME.equals(user)) {
                            String domain = this.realmConfig.getUserStoreProperty(UserStoreConfigConstants.DOMAIN_NAME);
                            user = UserCoreUtil.addDomainToName(user, domain);
                        }
                        userList.add(user);
                    }
                } else {
                    if (LOGGER.isDebugEnabled()) {
                        LOGGER.debug("Response is for get user list count: " + retryCount);
                    }
                }
                retryCount++;
            }

        } catch (JMSConnectionException e) {
            LOGGER.error("Error occurred while creating JMS connection", e);
        } catch (JMSException e) {
            LOGGER.error("Error occurred while adding message to queue", e);
        } catch (JSONException e) {
            LOGGER.error("Error occurred while reading JSON object", e);
        } finally {
            try {
                connectionFactory.closeConnection(connection);
            } catch (JMSConnectionException e) {
                LOGGER.error("Error occurred while closing the connection", e);
            }
        }
        return userList.toArray(new String[userList.size()]);
    }

    @Override
    protected String[] doGetDisplayNamesForInternalRole(String[] userNames) throws UserStoreException {
        throw new UserStoreException("UserStoreManager method not supported : #doGetDisplayNamesForInternalRole");
    }

    @Override
    public boolean doCheckIsUserInRole(String userName, String roleName) throws UserStoreException {
        String[] roles = this.doGetExternalRoleListOfUser(userName, "*");
        if (roles != null) {
            for (String role : roles) {
                if (role.equalsIgnoreCase(roleName)) {
                    return true;
                }
            }
        }

        return false;
    }

    public String[] doGetExternalRoleListOfUser(String userName, String filter) throws UserStoreException {

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Processing getRoleListOfUser request for tenantId  - [" + this.tenantId + "]");
        }

        JMSConnectionFactory connectionFactory = new JMSConnectionFactory();
        Connection connection = null;
        Session requestSession;
        Session responseSession;
        Destination requestTopic;
        Destination responseQueue;
        MessageProducer producer;
        List<String> groupList = new ArrayList<>();
        try {
            connectionFactory.createActiveMQConnectionFactory(getMessageBrokerURL());
            connection = connectionFactory.createConnection();
            connectionFactory.start(connection);
            requestSession = connectionFactory.createSession(connection);
            requestTopic = connectionFactory
                    .createTopicDestination(requestSession, UserStoreConstants.TOPIC_NAME_REQUEST);
            producer = connectionFactory
                    .createMessageProducer(requestSession, requestTopic, DeliveryMode.NON_PERSISTENT);

            int retryCount = 0;
            Message responseMessage = null;

            while (responseMessage == null && getMessageRetryLimit() > retryCount) {
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("Trying to get role list of user: " + userName + " count: " + retryCount);
                }
                String correlationId = UUID.randomUUID().toString();
                responseQueue = connectionFactory
                        .createQueueDestination(requestSession, UserStoreConstants.QUEUE_NAME_RESPONSE);

                addNextUserOperationToTopic(correlationId, UserStoreConstants.UM_OPERATION_TYPE_GET_USER_ROLES,
                        MessageRequestUtil.doGetExternalRoleListOfUserRequestData(
                                userName), requestSession, producer, responseQueue);

                responseSession = connectionFactory.createSession(connection);

                String selector = String.format(JMS_CORRELATIONID_FILTER, correlationId);
                MessageConsumer consumer = responseSession.createConsumer(responseQueue, selector);
                responseMessage = consumer.receive(getMessageConsumeTimeout());
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("Received response for user operation : " + UserStoreConstants
                            .UM_OPERATION_TYPE_GET_USER_ROLES + " correlationId : " + correlationId + " tenant id " +
                            ": " + tenantId);
                }

                if(responseMessage != null) {
                    UserOperation response = (UserOperation) ((ObjectMessage) responseMessage).getObject();
                    JSONObject responseObj = new JSONObject(response.getResponseData());
                    JSONObject resultObj = new JSONObject(
                            responseObj.get(UserStoreConstants.UM_JSON_ELEMENT_RESPONSE_DATA_RESULT).toString());
                    JSONArray groups = resultObj.getJSONArray("groups");
                    for (int i = 0; i < groups.length(); i++) {
                        groupList.add((String) groups.get(i));
                    }
                } else {
                    if (LOGGER.isDebugEnabled()) {
                        LOGGER.debug(
                                "Response is null for get role list of user: " + userName + " count: " + retryCount);
                    }
                }

                retryCount++;
            }
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Role list of user: " + userName + " is : " + groupList.toString());
            }

        } catch (JMSConnectionException e) {
            LOGGER.error("Error occurred while creating JMS Connection", e);
        } catch (JMSException e) {
            LOGGER.error("Error occurred while adding message to queue", e);
        } catch (JSONException e) {
            LOGGER.error("Error occurred while reading JSON object", e);
        } finally {
            try {
                connectionFactory.closeConnection(connection);
            } catch (JMSConnectionException e) {
                LOGGER.error("Error occurred while closing the connection", e);
            }
        }
        return groupList.toArray(new String[groupList.size()]);
    }

    @Override
    protected String[] doGetSharedRoleListOfUser(String userName, String tenantDomain, String filter)
            throws UserStoreException {
        throw new UserStoreException("UserStoreManager method not supported : #doGetSharedRoleListOfUser");
    }

    @Override
    protected void doAddRole(String roleName, String[] userList, boolean shared) throws UserStoreException {
        throw new UserStoreException("UserStoreManager method not supported : #doAddRole");

    }

    @Override
    protected void doDeleteRole(String roleName) throws UserStoreException {
        throw new UserStoreException("UserStoreManager method not supported : #doDeleteRole");

    }

    @Override
    protected void doUpdateRoleName(String roleName, String newRoleName) throws UserStoreException {
        throw new UserStoreException("UserStoreManager method not supported : #doUpdateRoleName");

    }

    public String[] doGetRoleNames(String filter, int maxItemLimit) throws UserStoreException {

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Processing doGetRoleNames request for tenantId  - [" + this.tenantId + "]");
        }

        JMSConnectionFactory connectionFactory = new JMSConnectionFactory();
        Connection connection = null;
        Session requestSession;
        Session responseSession;
        Destination requestTopic;
        Destination responseQueue;
        MessageProducer producer;
        List<String> groupList = new ArrayList<>();

        try {
            connectionFactory.createActiveMQConnectionFactory(getMessageBrokerURL());
            connection = connectionFactory.createConnection();
            connectionFactory.start(connection);
            requestSession = connectionFactory.createSession(connection);
            requestTopic = connectionFactory
                    .createTopicDestination(requestSession, UserStoreConstants.TOPIC_NAME_REQUEST);
            producer = connectionFactory
                    .createMessageProducer(requestSession, requestTopic, DeliveryMode.NON_PERSISTENT);

            int retryCount = 0;
            Message responseMessage = null;

            while (responseMessage == null && getMessageRetryLimit() > retryCount) {
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("Trying to get role list count: " + retryCount);
                }
                String correlationId = UUID.randomUUID().toString();
                responseQueue = connectionFactory
                        .createQueueDestination(requestSession, UserStoreConstants.QUEUE_NAME_RESPONSE);
                addNextUserOperationToTopic(correlationId, UserStoreConstants.UM_OPERATION_TYPE_GET_ROLES,
                        MessageRequestUtil.getRoleListRequest(
                                filter, maxItemLimit), requestSession,
                        producer, responseQueue);
                responseSession = connectionFactory.createSession(connection);

                String selector = String.format(JMS_CORRELATIONID_FILTER, correlationId);
                MessageConsumer consumer = responseSession.createConsumer(responseQueue, selector);
                responseMessage = consumer.receive(getMessageConsumeTimeout());
                if(responseMessage != null) {
                    if (LOGGER.isDebugEnabled()) {
                        LOGGER.debug("Received response for user operation : " + UserStoreConstants
                                .UM_OPERATION_TYPE_GET_ROLES + " correlationId : " + correlationId + " tenant id " +
                                ": " + tenantId);
                    }
                    UserOperation response = (UserOperation) ((ObjectMessage) responseMessage).getObject();
                    JSONObject responseObj = new JSONObject(response.getResponseData());
                    JSONObject resultObj = new JSONObject(
                            responseObj.get(UserStoreConstants.UM_JSON_ELEMENT_RESPONSE_DATA_RESULT).toString());
                    JSONArray groups = resultObj.getJSONArray("groups");

                    String userStoreDomain = this.realmConfig
                            .getUserStoreProperty(UserStoreConfigConstants.DOMAIN_NAME);
                    for (int i = 0; i < groups.length(); i++) {
                        String roleName = (String) groups.get(i);
                        roleName = UserCoreUtil.addDomainToName(roleName, userStoreDomain);
                        groupList.add(roleName);
                    }
                } else {
                    if (LOGGER.isDebugEnabled()) {
                        LOGGER.debug("Response is null for get role list count: " + retryCount);
                    }
                }
                retryCount++;
            }
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Role name list is: " + groupList.toString());
            }

        } catch (JMSConnectionException e) {
            LOGGER.error("Error occurred while creating JMS Connection", e);
        } catch (JMSException e) {
            LOGGER.error("Error occurred while adding message to queue", e);
        } catch (JSONException e) {
            LOGGER.error("Error occurred while reading JSON object", e);
        } finally {
            try {
                connectionFactory.closeConnection(connection);
            } catch (JMSConnectionException e) {
                LOGGER.error("Error occurred while closing the connection", e);
            }
        }
        return groupList.toArray(new String[groupList.size()]);
    }

}
