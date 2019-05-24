/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.is.password.secondaryUserStore.migrator;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.impl.builder.StAXOMBuilder;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.core.util.CryptoException;
import org.wso2.carbon.identity.core.migrate.MigrationClientException;
import org.wso2.carbon.identity.core.util.IdentityIOStreamUtils;
import org.wso2.carbon.user.api.Tenant;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.is.password.secondaryUserStore.internal.ISMigrationServiceDataHolder;
import org.wso2.is.password.secondaryUserStore.util.Constant;
import org.wso2.is.password.secondaryUserStore.util.EncryptionUtil;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

public class UserStorePasswordMigrator {

    private static final Log log = LogFactory.getLog(UserStorePasswordMigrator.class);

    /**
     * Return all the tenants or tenant range by checking migrateTenantRange option is enabled.
     *
     * @return tenant set
     * @throws MigrationClientException
     */
    private static Set<Tenant> getTenants() throws MigrationClientException {

        Set<Tenant> tenants;
        Tenant[] tenantsArray;
        try {
            tenantsArray = ISMigrationServiceDataHolder.getRealmService().getTenantManager().getAllTenants();
            tenants = new HashSet<>(Arrays.asList(tenantsArray));

        } catch (UserStoreException e) {
            String msg = "Error while retrieving the tenants.";
            throw new MigrationClientException(msg, e);
        }
        return tenants;
    }

    public void migrate() throws MigrationClientException {

        log.info(Constant.MIGRATION_LOG + "Migration starting on Secondary User Stores");
        updateSuperTenantConfigs();
        updateTenantConfigs();
    }

    private void updateTenantConfigs() throws MigrationClientException {

        try {
            Set<Tenant> tenants = getTenants();
            for (Tenant tenant : tenants) {

                try {
                    File[] userStoreConfigs = getUserStoreConfigFiles(tenant.getId());
                    for (File file : userStoreConfigs) {
                        if (file.isFile()) {
                            updatePassword(file.getAbsolutePath());
                        }
                    }
                } catch (FileNotFoundException | CryptoException e) {
                    String msg = "Error while updating secondary user store password for tenant: " + tenant.getDomain();
                    log.error(msg, e);
                }
            }
        } catch (MigrationClientException e) {
            throw new MigrationClientException("Error while getting tenants for migration", e);
        }
    }

    private void updateSuperTenantConfigs() {

        try {
            File[] userStoreConfigs = getUserStoreConfigFiles(Constant.SUPER_TENANT_ID);
            for (File file : userStoreConfigs) {
                if (file.isFile()) {
                    updatePassword(file.getAbsolutePath());
                }
            }
        } catch (Exception e) {
            log.error("Error while updating secondary user store password for super tenant", e);
        }
    }

    private File[] getUserStoreConfigFiles(int tenantId) {

        String carbonHome = System.getProperty(Constant.CARBON_HOME);
        String userStorePath;
        if (tenantId == Constant.SUPER_TENANT_ID) {
            userStorePath = Paths.get(carbonHome, new String[]{"repository", "deployment", "server", "userstores"})
                    .toString();
        } else {
            userStorePath = Paths
                    .get(carbonHome, new String[]{"repository", "tenants", String.valueOf(tenantId), "userstores"})
                    .toString();
        }
        File[] files = new File(userStorePath).listFiles();
        return files != null ? files : new File[0];
    }

    private void updatePassword(String filePath) throws FileNotFoundException, CryptoException {

        XMLStreamReader parser = null;
        FileInputStream stream = null;
        try {
            log.info("Migrating password in: " + filePath);
            stream = new FileInputStream(filePath);
            parser = XMLInputFactory.newInstance().createXMLStreamReader(stream);
            StAXOMBuilder builder = new StAXOMBuilder(parser);
            OMElement documentElement = builder.getDocumentElement();
            Iterator it = documentElement.getChildElements();
            String newEncryptedPassword = null;
            while (it.hasNext()) {
                OMElement element = (OMElement) it.next();
                if ("true".equals(element.getAttributeValue(new QName("encrypted"))) && (
                        "password".equals(element.getAttributeValue(new QName("name"))) || "ConnectionPassword"
                                .equals(element.getAttributeValue(new QName("name"))))) {
                    String encryptedPassword = element.getText();
                    newEncryptedPassword = EncryptionUtil.getNewEncryptedUserstorePassword(encryptedPassword);
                    if (StringUtils.isNotEmpty(newEncryptedPassword)) {
                        element.setText(newEncryptedPassword);
                    }
                }
            }

            if (newEncryptedPassword != null) {
                OutputStream outputStream = new FileOutputStream(filePath);
                documentElement.serialize(outputStream);
            }
        } catch (XMLStreamException ex) {
            log.error("Error while updating password for: " + filePath, ex);
        } finally {
            try {
                if (parser != null) {
                    parser.close();
                }
                if (stream != null) {
                    IdentityIOStreamUtils.closeInputStream(stream);
                }
            } catch (XMLStreamException ex) {
                log.error("Error while closing XML stream", ex);
            }

        }
    }
}
