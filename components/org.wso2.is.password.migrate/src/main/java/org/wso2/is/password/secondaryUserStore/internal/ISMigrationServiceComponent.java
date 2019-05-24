/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.is.password.secondaryUserStore.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.base.api.ServerConfigurationService;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.is.password.secondaryUserStore.migrator.UserStorePasswordMigrator;

import static org.wso2.is.password.secondaryUserStore.util.Constant.JVM_PROPERTY_MIGRATE_PASSWORD;

@Component(
        name = "org.wso2.is.password.migrate",
        immediate = true
)
public class ISMigrationServiceComponent {

    private static final Log log = LogFactory.getLog(ISMigrationServiceComponent.class);

    /**
     * Method to activate bundle.
     * -DpassMigrate
     * @param context OSGi component context.
     */
    @Activate
    protected void activate(ComponentContext context) {

        try {
            String migration = System.getProperty(JVM_PROPERTY_MIGRATE_PASSWORD);
            log.info("secondary userstore password migration jar added");

            if (migration != null) {
                UserStorePasswordMigrator userStorePasswordMigrator = new UserStorePasswordMigrator();
                log.info("secondary userstore password migration started");
                context.getBundleContext().registerService(UserStorePasswordMigrator.class, userStorePasswordMigrator,
                        null);
                userStorePasswordMigrator.migrate();
                log.info("secondary userstore password migration ended");
            }

        } catch (Throwable e) {
            log.error("Error while initiating Config component", e);
        }

    }

    /**
     * Method to deactivate bundle.
     *
     * @param context OSGi component context.
     */
    @Deactivate
    protected void deactivate(ComponentContext context) {

        if (log.isDebugEnabled()) {
            log.debug("WSO2 IS migration bundle is deactivated");
        }
    }

    /**
     * Method to set realm service.
     *
     * @param realmService service to get tenant data.
     */
    @Reference(
            name = "realm.service",
            service = RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService"
    )
    protected void setRealmService(RealmService realmService) {

        if (log.isDebugEnabled()) {
            log.debug("Setting RealmService to WSO2 IS Config component");
        }
        ISMigrationServiceDataHolder.setRealmService(realmService);
    }

    /**
     * Method to unset realm service.
     *
     * @param realmService service to get tenant data.
     */
    protected void unsetRealmService(RealmService realmService) {

        if (log.isDebugEnabled()) {
            log.debug("Unsetting RealmService from WSO2 IS Config component");
        }
        ISMigrationServiceDataHolder.setRealmService(null);
    }

    @Reference(
            name = "server.configuration.service",
            service = ServerConfigurationService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetServerConfigurationService"
    )
    protected void setServerConfigurationService(ServerConfigurationService serverConfigurationService) {

        ISMigrationServiceDataHolder.setServerConfigurationService(serverConfigurationService);
    }

    protected void unsetServerConfigurationService(ServerConfigurationService serverConfigurationService) {

        ISMigrationServiceDataHolder.setServerConfigurationService(null);
    }

    @Reference(
            name = "registry.service",
            service = RegistryService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRegistryService"
    )
    protected void setRegistryService(RegistryService registryService) {

        ISMigrationServiceDataHolder.setRegistryService(registryService);
    }

    protected void unsetRegistryService(RegistryService registryService) {

        ISMigrationServiceDataHolder.setRegistryService(null);
    }
}