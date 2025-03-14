import cockpit from "cockpit";
import React from "react";
import { log_cmd, valid_dn, isValidIpAddress, is_port_in_use } from "../tools.jsx";
import {
	Button,
	Checkbox,
	Form,
	FormHelperText,
	FormSelect,
	FormSelectOption,
	Grid,
	GridItem,
	HelperText,
	HelperTextItem,
	Spinner,
	Tab,
	Tabs,
	TabTitleText,
	NumberInput,
	TextInput,
	Text,
	TextContent,
	TextVariants,
	ValidatedOptions
} from '@patternfly/react-core';
import {
	Select,
	SelectOption,
	SelectVariant
} from '@patternfly/react-core/deprecated';
import { SyncAltIcon } from '@patternfly/react-icons';
import PropTypes from "prop-types";

const general_attrs = [
    'nsslapd-port',
    'nsslapd-secureport',
    'nsslapd-localhost',
    'nsslapd-listenhost',
    'nsslapd-bakdir',
    'nsslapd-ldifdir',
    'nsslapd-schemadir',
    'nsslapd-certdir'
];

const path_attrs = [
    'nsslapd-bakdir',
    'nsslapd-ldifdir',
    'nsslapd-schemadir',
    'nsslapd-certdir'
];

const rootdn_attrs = [
    'nsslapd-rootpwstoragescheme',
    'nsslapd-rootpw',
    'confirmRootpw',
];

const disk_attrs = [
    'nsslapd-disk-monitoring',
    'nsslapd-disk-monitoring-logging-critical',
    'nsslapd-disk-monitoring-threshold',
    'nsslapd-disk-monitoring-grace-period',
];

const adv_attrs = [
    'nsslapd-allow-anonymous-access',
    'nsslapd-entryusn-global',
    'nsslapd-ignore-time-skew',
    'nsslapd-readonly',
    'nsslapd-anonlimitsdn',
    'nsslapd-schemacheck',
    'nsslapd-syntaxcheck',
    'nsslapd-plugin-logging',
    'nsslapd-syntaxlogging',
    'nsslapd-plugin-binddn-tracking',
    'nsslapd-attribute-name-exceptions',
    'nsslapd-dn-validate-strict',
    'nsslapd-haproxy-trusted-ip',
];

const _ = cockpit.gettext;

export class ServerSettings extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            loading: true,
            activeTabKey: 0,
            attrs: this.props.attrs,
            // Setting lists
            configSaveDisabled: true,
            configReloading: false,
            errObjConfig: {},
            rootDNReloading: false,
            rootDNSaveDisabled: true,
            errObjRootDN: {},
            diskMonReloading: false,
            diskMonSaveDisabled: true,
            errObjDiskMon: {},
            advSaveDisabled: true,
            advReloading: false,
            errObjAdv: {},
            haproxyIPs: [],
            _haproxyIPs: [],
            haproxyIPsOptions: [],
            isHaproxyIPsOpen: false,
            invalidIP: false,
        };

        this.handleOnHaproxyIPsToggle = (_event, isHaproxyIPsOpen) => {
            this.setState({
                isHaproxyIPsOpen,
                invalidIP: false,
            });
        };
        this.handleOnHaproxyIPsSelect = (event, selection, nav_tab) => {
            const id = 'nsslapd-haproxy-trusted-ip';
            const { haproxyIPs } = this.state;
            // The first if-block is when removing an item from the list
            if (haproxyIPs.includes(selection)) {
                this.setState(
                    prevState => ({
                        haproxyIPs: prevState.haproxyIPs.filter(item => item !== selection),
                        isHaproxyIPsOpen: false
                    }), () => { this.validateSaveBtn(nav_tab, id, haproxyIPs.filter(item => item !== selection)) });
            // The second if-block is when adding an item to the list
            } else {
                this.setState(
                    prevState => ({
                        haproxyIPs: [...prevState.haproxyIPs, selection],
                        isHaproxyIPsOpen: false,
                    }), () => { this.validateSaveBtn(nav_tab, id, [...haproxyIPs, selection]) });
            }
        };

        this.handleOnHaproxyIPsClear = (event, nav_tab) => {
            const id = 'nsslapd-haproxy-trusted-ip';
            const selection = [];
            this.setState({
                haproxyIPs: [],
                isHaproxyIPsOpen: false,
                invalidIP: false,
            }, () => { this.validateSaveBtn(nav_tab, id, selection) });
        };

        this.handleOnCreateHaproxyIP = newValue => {
            if (!this.state.haproxyIPsOptions.includes(newValue)) {
                this.setState({
                    haproxyIPsOptions: [...this.state.haproxyIPsOptions, newValue],
                    isHaproxyIPsOpen: false
                });
            }
        };

        // Toggle currently active tab
        this.handleNavSelect = (event, tabIndex) => {
            this.setState({
                activeTabKey: tabIndex
            });
        };

        this.options = [
            { value: 'PBKDF2-SHA512', label: 'PBKDF2-SHA512', disabled: false },
            { value: 'PBKDF2-SHA256', label: 'PBKDF2-SHA256', disabled: false },
            { value: 'PBKDF2_SHA256', label: 'PBKDF2_SHA256', disabled: false },
            { value: 'SSHA512', label: 'SSHA512', disabled: false },
            { value: 'SSHA384', label: 'SSHA384', disabled: false },
            { value: 'SSHA256', label: 'SSHA256', disabled: false },
            { value: 'SSHA', label: 'SSHA', disabled: false },
            { value: 'MD5', label: 'MD5', disabled: false },
            { value: 'SMD5', label: 'SMD5', disabled: false },
            { value: 'CRYPT-MD5', label: 'CRYPT-MD5', disabled: false },
            { value: 'CRYPT-SHA512', label: 'CRYPT-SHA512', disabled: false },
            { value: 'CRYPT-SHA256', label: 'CRYPT-SHA256', disabled: false },
            { value: 'CRYPT', label: 'CRYPT', disabled: false },
            { value: 'GOST_YESCRYPT', label: 'GOST_YESCRYPT', disabled: false },
            { value: 'CLEAR', label: 'CLEAR', disabled: false },
        ];

        this.validatePaths = this.validatePaths.bind(this);
        this.validateAllTabs = this.validateAllTabs.bind(this);
        this.handleChange = this.handleChange.bind(this);
        this.loadConfig = this.loadConfig.bind(this);
        this.handleSaveConfig = this.handleSaveConfig.bind(this);
        this.handleReloadConfig = this.handleReloadConfig.bind(this);
        this.handleSaveRootDN = this.handleSaveRootDN.bind(this);
        this.reloadRootDN = this.reloadRootDN.bind(this);
        this.handleSaveDiskMonitoring = this.handleSaveDiskMonitoring.bind(this);
        this.reloadDiskMonitoring = this.reloadDiskMonitoring.bind(this);
        this.handleSaveAdvanced = this.handleSaveAdvanced.bind(this);
        this.reloadAdvanced = this.reloadAdvanced.bind(this);
        this.validateSaveBtn = this.validateSaveBtn.bind(this);

        this.onMinusConfig = (id, nav_tab) => {
            this.setState({
                [id]: Number(this.state[id]) - 1
            }, () => { this.validateSaveBtn(nav_tab, id, Number(this.state[id])) });
        }

        this.onConfigChange = (event, id, min, max, nav_tab) => {
            let maxValue = this.maxValue;
            if (max !== 0) {
                maxValue = max;
            }
            let newValue = isNaN(event.target.value) ? min : Number(event.target.value);
            newValue = newValue > maxValue ? maxValue : newValue < min ? min : newValue;
            this.setState({
                [id]: newValue
            }, () => { this.validateSaveBtn(nav_tab, id, Number(this.state[id])) });
        }

        this.onPlusConfig = (id, nav_tab) => {
            this.setState({
                [id]: Number(this.state[id]) + 1
            }, () => { this.validateSaveBtn(nav_tab, id, Number(this.state[id])) });
        }
    }

    componentDidMount() {
        // Loading config
        if (!this.state.loaded) {
            this.loadConfig();
        } else {
            this.validateAllTabs();
            this.props.enableTree();
        }
    }

    handleNavSelect(key) {
        this.setState({ activeKey: key });
    }

    validatePaths(disableSaveBtn) {
        let disableBtn = disableSaveBtn;
        const errObj = this.state.errObjConfig;

        for (const attr of path_attrs) {
            const cmd = `[ -d "${this.state[attr]}" ]`;
            cockpit
                    .script(cmd, [], { superuser: true, err: "message" })
                    .done(output => {
                        errObj[attr] = false;
                        this.setState({
                            errObjConfig: errObj,
                            configSaveDisabled: disableBtn
                        });
                    })
                    .fail(() => {
                        errObj[attr] = true;
                        disableBtn = true;
                        this.setState({
                            configSaveDisabled: disableBtn,
                            errObjConfig: errObj
                        });
                    });
        }
    }

async validateSaveBtn(nav_tab, attr, value) {
        let disableSaveBtn = true;
        let disableBtnName = "";
        let config_attrs = [];
        let valueErr = false;
        let invalidIP = false;
        let errObj = {};
        if (nav_tab === "config") {
            config_attrs = general_attrs;
            disableBtnName = "configSaveDisabled";
            errObj = this.state.errObjConfig;
        } else if (nav_tab === "rootdn") {
            disableBtnName = "rootDNSaveDisabled";
            config_attrs = rootdn_attrs;
            errObj = this.state.errObjRootDN;
        } else if (nav_tab === "diskmon") {
            disableBtnName = "diskMonSaveDisabled";
            config_attrs = disk_attrs;
            errObj = this.state.errObjDiskMon;
        } else if (nav_tab === "adv") {
            disableBtnName = "advSaveDisabled";
            config_attrs = adv_attrs;
            errObj = this.state.errObjAdv;
        }

        // Check if a setting was changed, if so enable the save button
        for (const config_attr of config_attrs) {
            if (attr === config_attr && String(this.state['_' + config_attr]) !== String(value)) {
                disableSaveBtn = false;
                break;
            }
        }

        // Now check for differences in values that we did not touch
        for (const config_attr of config_attrs) {
            if (attr !== config_attr && String(this.state['_' + config_attr]) !== String(this.state[config_attr])) {
                disableSaveBtn = false;
                break;
            }
        }

        if (nav_tab === "config") {
            if (attr !== 'nsslapd-listenhost' && value === "") {
                // Only listenhost is allowed to be blank
                valueErr = true;
                disableSaveBtn = true;
            }
            if (attr === 'nsslapd-port' || attr === 'nsslapd-secureport') {
                const portValue = Number(value)
                if (!isNaN(portValue)) {
                    try {
                        // Check port value is not already in use.
                        const portInUse = await is_port_in_use(portValue);
                        if (portInUse) {
                            disableSaveBtn = true;
                            if (portValue !== Number(this.state['_' + attr])) {
                                valueErr = true;
                            }
                        }
                    } catch (error) {
                        console.error("Error checking port:", error);
                        disableSaveBtn = true;
                        valueErr = true;
                    }
                }
            }
        } else if (nav_tab === "rootdn") {
            // Handle validating passwords are in sync
            if (attr === 'nsslapd-rootpw') {
                if (value !== this.state.confirmRootpw) {
                    disableSaveBtn = true;
                    valueErr = true;
                    errObj['nsslapd-rootpw'] = true;
                } else {
                    errObj.confirmRootpw = false;
                    errObj['nsslapd-rootpw'] = false;
                }
            }
            if (attr === 'confirmRootpw') {
                if (value !== this.state['nsslapd-rootpw']) {
                    disableSaveBtn = true;
                    valueErr = true;
                    errObj.confirmRootpw = true;
                } else {
                    errObj.confirmRootpw = false;
                    errObj['nsslapd-rootpw'] = false;
                }
            }

            if (value === "") {
                disableSaveBtn = true;
                valueErr = true;
            }
        } else if (nav_tab === "diskmon") {
            if (value === "" && (typeof value !== "boolean")) {
                valueErr = true;
                disableSaveBtn = true;
            }
            if (attr === 'nsslapd-disk-monitoring-threshold') {
                const numVal = Number(value);
                if (numVal < 4096) {
                    valueErr = true;
                    disableSaveBtn = true;
                }
            }
        } else if (nav_tab === "adv") {
            // Handle special cases for anon limit dn
            if (attr === 'nsslapd-anonlimitsdn' && !valid_dn(value)) {
                valueErr = true;
                errObj[attr] = true;
            }
            if (value === "" && attr !== 'nsslapd-anonlimitsdn' && (typeof value !== "boolean")) {
                valueErr = true;
                disableSaveBtn = true;
            }
            if (attr === 'nsslapd-haproxy-trusted-ip') {
                for (const ip of value) {
                    if (value && !isValidIpAddress(ip)) {
                        invalidIP = true;
                        disableSaveBtn = true;
                        break;
                    }
                }
            }
        }

        errObj[attr] = valueErr;
        this.setState({
            [attr]: value,
            invalidIP,
            errObjConfig: errObj,
            [disableBtnName]: disableSaveBtn
        }, () => { this.validatePaths(disableSaveBtn) });
    }

    handleChange(e, nav_tab) {
        const value = e.target.type === 'checkbox' ? e.target.checked : e.target.value;
        const attr = e.target.id;

        this.setState({
            [attr]: value,
        }, () => { this.validateSaveBtn(nav_tab, attr, value) });
    }

    validateAllTabs() {
        const tabs = ['config', 'rootdn', 'diskmon', 'adv'];
        tabs.forEach(tab => {
            let attrs;
            switch (tab) {
            case 'config':
                attrs = general_attrs;
                break;
            case 'rootdn':
                attrs = rootdn_attrs;
                break;
            case 'diskmon':
                attrs = disk_attrs;
                break;
            case 'adv':
                attrs = adv_attrs;
                break;
            }
            attrs.forEach(attr => {
                this.validateSaveBtn(tab, attr, this.state[attr]);
            });
        });
    }

    loadConfig() {
        const attrs = this.state.attrs;
        // Handle the checkbox values
        let diskMonitoring = false;
        let diskLogCritical = false;
        let schemaCheck = false;
        let syntaxCheck = false;
        let pluginLogging = false;
        let syntaxLogging = false;
        let bindDNTracking = false;
        let nameExceptions = false;
        let dnValidate = false;
        let usnGlobal = false;
        let ignoreSkew = false;
        let readOnly = false;
        let listenhost = "";

        if (attrs['nsslapd-entryusn-global'][0] === "on") {
            usnGlobal = true;
        }
        if (attrs['nsslapd-ignore-time-skew'][0] === "on") {
            ignoreSkew = true;
        }
        if (attrs['nsslapd-readonly'][0] === "on") {
            readOnly = true;
        }
        if (attrs['nsslapd-disk-monitoring'][0] === "on") {
            diskMonitoring = true;
        }
        if (attrs['nsslapd-disk-monitoring-logging-critical'][0] === "on") {
            diskLogCritical = true;
        }
        if (attrs['nsslapd-schemacheck'][0] === "on") {
            schemaCheck = true;
        }
        if (attrs['nsslapd-syntaxcheck'][0] === "on") {
            syntaxCheck = true;
        }
        if (attrs['nsslapd-plugin-logging'][0] === "on") {
            pluginLogging = true;
        }
        if (attrs['nsslapd-syntaxlogging'][0] === "on") {
            syntaxLogging = true;
        }
        if (attrs['nsslapd-plugin-binddn-tracking'][0] === "on") {
            bindDNTracking = true;
        }
        if (attrs['nsslapd-attribute-name-exceptions'][0] === "on") {
            nameExceptions = true;
        }
        if (attrs['nsslapd-dn-validate-strict'][0] === "on") {
            dnValidate = true;
        }
        if ('nsslapd-listenhost' in attrs) {
            listenhost = attrs['nsslapd-listenhost'][0];
        }

        this.setState({
            loaded: true,
            loading: false,
            errObjConfig: {},
            errObjRootDN: {},
            errObjDiskMon: {},
            errObjAdv: {},
            // Settings
            'nsslapd-port': attrs['nsslapd-port'][0],
            'nsslapd-secureport': attrs['nsslapd-secureport'][0],
            'nsslapd-localhost': attrs['nsslapd-localhost'][0],
            'nsslapd-listenhost': listenhost,
            'nsslapd-bakdir': attrs['nsslapd-bakdir'][0],
            'nsslapd-ldifdir': attrs['nsslapd-ldifdir'][0],
            'nsslapd-schemadir': attrs['nsslapd-schemadir'][0],
            'nsslapd-certdir': attrs['nsslapd-certdir'][0],
            'nsslapd-rootdn': attrs['nsslapd-rootdn'][0],
            'nsslapd-rootpw': attrs['nsslapd-rootpw'][0],
            confirmRootpw: attrs['nsslapd-rootpw'][0],
            'nsslapd-rootpwstoragescheme': attrs['nsslapd-rootpwstoragescheme'][0],
            'nsslapd-anonlimitsdn': attrs['nsslapd-anonlimitsdn'][0],
            haproxyIPs: attrs['nsslapd-haproxy-trusted-ip'] ? attrs['nsslapd-haproxy-trusted-ip'] : [],
            'nsslapd-haproxy-trusted-ip': attrs['nsslapd-haproxy-trusted-ip'] ? attrs['nsslapd-haproxy-trusted-ip'] : [],
            'nsslapd-disk-monitoring-threshold': attrs['nsslapd-disk-monitoring-threshold'][0],
            'nsslapd-disk-monitoring-grace-period': attrs['nsslapd-disk-monitoring-grace-period'][0],
            'nsslapd-allow-anonymous-access': attrs['nsslapd-allow-anonymous-access'][0],
            'nsslapd-disk-monitoring': diskMonitoring,
            'nsslapd-disk-monitoring-logging-critical': diskLogCritical,
            'nsslapd-schemacheck': schemaCheck,
            'nsslapd-syntaxcheck': syntaxCheck,
            'nsslapd-plugin-logging': pluginLogging,
            'nsslapd-syntaxlogging': syntaxLogging,
            'nsslapd-plugin-binddn-tracking': bindDNTracking,
            'nsslapd-attribute-name-exceptions': nameExceptions,
            'nsslapd-dn-validate-strict': dnValidate,
            'nsslapd-entryusn-global': usnGlobal,
            'nsslapd-ignore-time-skew': ignoreSkew,
            'nsslapd-readonly': readOnly,
            // Record original values
            '_nsslapd-port': attrs['nsslapd-port'][0],
            '_nsslapd-secureport': attrs['nsslapd-secureport'][0],
            '_nsslapd-localhost': attrs['nsslapd-localhost'][0],
            '_nsslapd-listenhost': listenhost,
            '_nsslapd-bakdir': attrs['nsslapd-bakdir'][0],
            '_nsslapd-ldifdir': attrs['nsslapd-ldifdir'][0],
            '_nsslapd-schemadir': attrs['nsslapd-schemadir'][0],
            '_nsslapd-certdir': attrs['nsslapd-certdir'][0],
            '_nsslapd-rootdn': attrs['nsslapd-rootdn'][0],
            '_nsslapd-rootpw': attrs['nsslapd-rootpw'][0],
            _confirmRootpw: attrs['nsslapd-rootpw'][0],
            '_nsslapd-rootpwstoragescheme': attrs['nsslapd-rootpwstoragescheme'][0],
            '_nsslapd-anonlimitsdn': attrs['nsslapd-anonlimitsdn'][0],
            _haproxyIPs: attrs['nsslapd-haproxy-trusted-ip'] ? attrs['nsslapd-haproxy-trusted-ip'] : [],
            '_nsslapd-haproxy-trusted-ip': attrs['nsslapd-haproxy-trusted-ip'] ? attrs['nsslapd-haproxy-trusted-ip'] : [],
            '_nsslapd-disk-monitoring-threshold': attrs['nsslapd-disk-monitoring-threshold'][0],
            '_nsslapd-disk-monitoring-grace-period': attrs['nsslapd-disk-monitoring-grace-period'][0],
            '_nsslapd-allow-anonymous-access': attrs['nsslapd-allow-anonymous-access'][0],
            '_nsslapd-disk-monitoring': diskMonitoring,
            '_nsslapd-disk-monitoring-logging-critical': diskLogCritical,
            '_nsslapd-schemacheck': schemaCheck,
            '_nsslapd-syntaxcheck': syntaxCheck,
            '_nsslapd-plugin-logging': pluginLogging,
            '_nsslapd-syntaxlogging': syntaxLogging,
            '_nsslapd-plugin-binddn-tracking': bindDNTracking,
            '_nsslapd-attribute-name-exceptions': nameExceptions,
            '_nsslapd-dn-validate-strict': dnValidate,
            '_nsslapd-entryusn-global': usnGlobal,
            '_nsslapd-ignore-time-skew': ignoreSkew,
            '_nsslapd-readonly': readOnly,
        }, () => {
            this.validateAllTabs();
            this.props.enableTree();
        });
    }

    handleSaveRootDN() {
        this.setState({
            rootDNReloading: true,
        });
        const cmd = [
            'dsconf', '-j', 'ldapi://%2fvar%2frun%2fslapd-' + this.props.serverId + '.socket',
            'config', 'replace'
        ];

        for (const attr of rootdn_attrs) {
            if (attr !== 'confirmRootpw' && this.state['_' + attr] !== this.state[attr]) {
                cmd.push(attr + "=" + this.state[attr]);
            }
        }

        log_cmd("handleSaveRootDN", "Saving changes to root DN", cmd);
        cockpit
                .spawn(cmd, { superuser: true, err: "message" })
                .done(content => {
                    this.reloadRootDN();
                    this.props.addNotification(
                        "success",
                        _("Successfully updated Directory Manager configuration")
                    );
                })
                .fail(err => {
                    const errMsg = JSON.parse(err);
                    this.reloadRootDN();
                    this.props.addNotification(
                        "error",
                        cockpit.format(_("Error updating Directory Manager configuration - $0"), errMsg.desc)
                    );
                });
    }

    reloadRootDN() {
        const cmd = [
            "dsconf", "-j", "ldapi://%2fvar%2frun%2fslapd-" + this.props.serverId + ".socket",
            "config", "get"
        ];
        log_cmd("handleReloadConfig", "Reload Directory Manager configuration", cmd);
        cockpit
                .spawn(cmd, { superuser: true, err: "message" })
                .done(content => {
                    const config = JSON.parse(content);
                    const attrs = config.attrs;
                    this.setState(() => (
                        {
                            rootDNReloading: false,
                            'nsslapd-rootdn': attrs['nsslapd-rootdn'][0],
                            'nsslapd-rootpw': attrs['nsslapd-rootpw'][0],
                            confirmRootpw: attrs['nsslapd-rootpw'][0],
                            'nsslapd-rootpwstoragescheme': attrs['nsslapd-rootpwstoragescheme'][0],
                            // Record original values
                            '_nsslapd-rootdn': attrs['nsslapd-rootdn'][0],
                            '_nsslapd-rootpw': attrs['nsslapd-rootpw'][0],
                            _confirmRootpw: attrs['nsslapd-rootpw'][0],
                            '_nsslapd-rootpwstoragescheme': attrs['nsslapd-rootpwstoragescheme'][0],
                            rootDNSaveDisabled: true
                        })
                    );
                })
                .fail(err => {
                    const errMsg = JSON.parse(err);
                    this.setState({
                        rootDNReloading: false,
                    });
                    this.props.addNotification(
                        "error",
                        cockpit.format(_("Error reloading Directory Manager configuration - $0"), errMsg.desc)
                    );
                });
    }

    handleSaveDiskMonitoring() {
        this.setState({
            diskMonReloading: true,
        });
        const cmd = [
            'dsconf', '-j', 'ldapi://%2fvar%2frun%2fslapd-' + this.props.serverId + '.socket',
            'config', 'replace'
        ];
        for (const attr of disk_attrs) {
            if (this.state['_' + attr] !== this.state[attr]) {
                let val = this.state[attr];
                if (typeof val === "boolean") {
                    if (val) {
                        val = "on";
                    } else {
                        val = "off";
                    }
                }
                cmd.push(attr + "=" + val);
            }
        }

        log_cmd("handleSaveDiskMonitoring", "Saving changes to Disk Monitoring", cmd);
        cockpit
                .spawn(cmd, { superuser: true, err: "message" })
                .done(content => {
                    this.reloadDiskMonitoring();
                    this.props.addNotification(
                        "success",
                        _("Successfully updated Disk Monitoring configuration")
                    );
                })
                .fail(err => {
                    const errMsg = JSON.parse(err);
                    this.reloadDiskMonitoring();
                    this.props.addNotification(
                        "error",
                        cockpit.format(_("Error updating Disk Monitoring configuration - $0"), errMsg.desc)
                    );
                });
    }

    reloadDiskMonitoring() {
        const cmd = [
            "dsconf", "-j", "ldapi://%2fvar%2frun%2fslapd-" + this.props.serverId + ".socket",
            "config", "get"
        ];
        log_cmd("reloadDiskMonitoring", "Reload Disk Monitoring configuration", cmd);
        cockpit
                .spawn(cmd, { superuser: true, err: "message" })
                .done(content => {
                    const config = JSON.parse(content);
                    const attrs = config.attrs;
                    // Handle the checkbox values
                    let diskMonitoring = false;
                    let diskLogCritical = false;

                    if (attrs['nsslapd-disk-monitoring'][0] === "on") {
                        diskMonitoring = true;
                    }
                    if (attrs['nsslapd-disk-monitoring-logging-critical'][0] === "on") {
                        diskLogCritical = true;
                    }
                    this.setState(() => (
                        {
                            diskMonReloading: false,
                            'nsslapd-disk-monitoring-threshold': attrs['nsslapd-disk-monitoring-threshold'][0],
                            'nsslapd-disk-monitoring-grace-period': attrs['nsslapd-disk-monitoring-grace-period'][0],
                            'nsslapd-disk-monitoring': diskMonitoring,
                            'nsslapd-disk-monitoring-logging-critical': diskLogCritical,
                            // Record original values
                            '_nsslapd-disk-monitoring-threshold': attrs['nsslapd-disk-monitoring-threshold'][0],
                            '_nsslapd-disk-monitoring-grace-period': attrs['nsslapd-disk-monitoring-grace-period'][0],
                            '_nsslapd-disk-monitoring': diskMonitoring,
                            '_nsslapd-disk-monitoring-logging-critical': diskLogCritical,
                            diskMonSaveDisabled: true
                        })
                    );
                })
                .fail(err => {
                    const errMsg = JSON.parse(err);
                    this.setState({
                        diskMonReloading: false,
                    });
                    this.props.addNotification(
                        "error",
                        cockpit.format(_("Error reloading Disk Monitoring configuration - $0"), errMsg.desc)
                    );
                });
    }

    /* We use this function for multi-valued config attributes because they require a special treatment */
    handleMultivaluedAttributeReplace(attrs) {
        const cmd = [
            'dsconf', '-j', 'ldapi://%2fvar%2frun%2fslapd-' + this.props.serverId + '.socket',
            'config', 'delete', 'nsslapd-haproxy-trusted-ip'
        ];
        log_cmd("handleMultivaluedAttributeReplace", "Removing cn=config attribute", cmd);
        cockpit
                .spawn(cmd, { superuser: true, err: "message" })
                .done(content => {
                    if (attrs.length > 0) {
                        const cmd = [
                            'dsconf', '-j', 'ldapi://%2fvar%2frun%2fslapd-' + this.props.serverId + '.socket',
                            'config', 'add', ...attrs
                        ];
                        log_cmd("handleMultivaluedAttributeReplace", "Adding multivalued cn=config attribute", cmd);
                        cockpit
                                .spawn(cmd, { superuser: true, err: "message" })
                                .done(content => {
                                    this.reloadAdvanced();
                                    this.props.addNotification(
                                        "success",
                                        "Successfully updated Advanced configuration"
                                    );
                                })
                                .fail(err => {
                                    const errMsg = JSON.parse(err);
                                    this.reloadAdvanced();
                                    this.props.addNotification(
                                        "error",
                                        `Error updating Advanced configuration - ${errMsg.desc}`
                                    );
                                });
                    } else {
                        this.reloadAdvanced();
                        this.props.addNotification(
                            "success",
                            "Successfully updated Advanced configuration"
                        );
                    }
                })
                .fail(err => {
                    const errMsg = JSON.parse(err);
                    this.reloadAdvanced();
                    this.props.addNotification(
                        "error",
                        `Error updating Advanced configuration - ${errMsg.desc}`
                    );
                });
    }

    handleSaveAdvanced() {
        this.setState({
            advReloading: true,
        });
        let doHaproxy = false;
        const addHAproxy = [];
        const cmd = [
            'dsconf', '-j', 'ldapi://%2fvar%2frun%2fslapd-' + this.props.serverId + '.socket',
            'config', 'replace'
        ];

        for (const attr of adv_attrs) {
            if (this.state['_' + attr] !== this.state[attr]) {
                if (attr === 'nsslapd-haproxy-trusted-ip') {
                    if (this.state.haproxyIPs.sort().toString() !== this.state._haproxyIPs.sort().toString()) {
                        doHaproxy = true;
                        for (const val of this.state.haproxyIPs) {
                            addHAproxy.push(attr + "=" + val);
                        }
                    }
                } else {
                    let val = this.state[attr];
                    if (typeof val === "boolean") {
                        if (val) {
                            val = "on";
                        } else {
                            val = "off";
                        }
                    }
                    cmd.push(attr + "=" + val);
                }
            }
        }

        // If HAProxy IPs is the only thing that changed, we don't need to run the main replace
        if (cmd.length === 5 && doHaproxy) {
            this.handleMultivaluedAttributeReplace(addHAproxy);
            return;
        }
        log_cmd("handleSaveAdvanced", "Saving Advanced configuration", cmd);
        cockpit
                .spawn(cmd, { superuser: true, err: "message" })
                .done(content => {
                    if (doHaproxy) {
                        this.handleMultivaluedAttributeReplace(addHAproxy);
                    } else {
                        this.reloadAdvanced();
                        this.props.addNotification(
                            "success",
                            _("Successfully updated Advanced configuration")
                        );
                    }
                })
                .fail(err => {
                    const errMsg = JSON.parse(err);
                    this.reloadAdvanced();
                    this.props.addNotification(
                        "error",
                        cockpit.format(_("Error updating Advanced configuration - $0"), errMsg.desc)
                    );
                });
    }

    reloadAdvanced() {
        const cmd = [
            "dsconf", "-j", "ldapi://%2fvar%2frun%2fslapd-" + this.props.serverId + ".socket",
            "config", "get"
        ];
        log_cmd("reloadAdvanced", "Reload Advanced configuration", cmd);
        cockpit
                .spawn(cmd, { superuser: true, err: "message" })
                .done(content => {
                    const config = JSON.parse(content);
                    const attrs = config.attrs;
                    // Handle the checkbox values
                    let schemaCheck = false;
                    let syntaxCheck = false;
                    let pluginLogging = false;
                    let syntaxLogging = false;
                    let bindDNTracking = false;
                    let nameExceptions = false;
                    let dnValidate = false;
                    let usnGlobal = false;
                    let ignoreSkew = false;
                    let readOnly = false;

                    if (attrs['nsslapd-entryusn-global'][0] === "on") {
                        usnGlobal = true;
                    }
                    if (attrs['nsslapd-ignore-time-skew'][0] === "on") {
                        ignoreSkew = true;
                    }
                    if (attrs['nsslapd-readonly'][0] === "on") {
                        readOnly = true;
                    }
                    if (attrs['nsslapd-schemacheck'][0] === "on") {
                        schemaCheck = true;
                    }
                    if (attrs['nsslapd-syntaxcheck'][0] === "on") {
                        syntaxCheck = true;
                    }
                    if (attrs['nsslapd-plugin-logging'][0] === "on") {
                        pluginLogging = true;
                    }
                    if (attrs['nsslapd-syntaxlogging'][0] === "on") {
                        syntaxLogging = true;
                    }
                    if (attrs['nsslapd-plugin-binddn-tracking'][0] === "on") {
                        bindDNTracking = true;
                    }
                    if (attrs['nsslapd-attribute-name-exceptions'][0] === "on") {
                        nameExceptions = true;
                    }
                    if (attrs['nsslapd-dn-validate-strict'][0] === "on") {
                        dnValidate = true;
                    }

                    this.setState(() => (
                        {
                            'nsslapd-anonlimitsdn': attrs['nsslapd-anonlimitsdn'][0],
                            haproxyIPs: attrs['nsslapd-haproxy-trusted-ip'] ? attrs['nsslapd-haproxy-trusted-ip'] : [],
                            'nsslapd-haproxy-trusted-ip': attrs['nsslapd-haproxy-trusted-ip'] ? attrs['nsslapd-haproxy-trusted-ip'] : [],
                            'nsslapd-allow-anonymous-access': attrs['nsslapd-allow-anonymous-access'][0],
                            'nsslapd-schemacheck': schemaCheck,
                            'nsslapd-syntaxcheck': syntaxCheck,
                            'nsslapd-plugin-logging': pluginLogging,
                            'nsslapd-syntaxLogging': syntaxLogging,
                            'nsslapd-plugin-binddn-tracking': bindDNTracking,
                            'nsslapd-attribute-name-exceptions': nameExceptions,
                            'nsslapd-dn-validate-strict': dnValidate,
                            'nsslapd-entryusn-global': usnGlobal,
                            'nsslapd-ignore-time-skew': ignoreSkew,
                            'nsslapd-readonly': readOnly,
                            // Record original values
                            '_nsslapd-anonlimitsdn': attrs['nsslapd-anonlimitsdn'][0],
                            _haproxyIPs: attrs['nsslapd-haproxy-trusted-ip'] ? attrs['nsslapd-haproxy-trusted-ip'] : [],
                            '_nsslapd-haproxy-trusted-ip': attrs['nsslapd-haproxy-trusted-ip'] ? attrs['nsslapd-haproxy-trusted-ip'] : [],
                            '_nsslapd-allow-anonymous-access': attrs['nsslapd-allow-anonymous-access'][0],
                            '_nsslapd-schemacheck': schemaCheck,
                            '_nsslapd-syntaxcheck': syntaxCheck,
                            '_nsslapd-plugin-logging': pluginLogging,
                            '_nsslapd-syntaxLogging': syntaxLogging,
                            '_nsslapd-plugin-binddn-tracking': bindDNTracking,
                            '_nsslapd-attribute-name-exceptions': nameExceptions,
                            '_nsslapd-dn-validate-strict': dnValidate,
                            '_nsslapd-entryusn-global': usnGlobal,
                            '_nsslapd-ignore-time-skew': ignoreSkew,
                            '_nsslapd-readonly': readOnly,
                            advReloading: false,
                            advSaveDisabled: true,
                            isHaproxyIPsOpen: false
                        })
                    );
                })
                .fail(err => {
                    const errMsg = JSON.parse(err);
                    this.props.addNotification(
                        "error",
                        cockpit.format(_("Error loading Advanced configuration - $0"), errMsg.desc)
                    );
                    this.setState({
                        advReloading: false,
                    });
                });
    }

    handleSaveConfig() {
        // Build up the command list
        this.setState({
            configReloading: true,
        });
        const cmd = [
            'dsconf', '-j', 'ldapi://%2fvar%2frun%2fslapd-' + this.props.serverId + '.socket',
            'config', 'replace'
        ];

        for (const attr of general_attrs) {
            if (this.state['_' + attr] !== this.state[attr]) {
                cmd.push(attr + "=" + this.state[attr]);
            }
        }

        log_cmd("handleSaveConfig", "Applying server config change", cmd);
        cockpit
                .spawn(cmd, { superuser: true, err: "message" })
                .done(content => {
                    // Continue with the next mod
                    this.handleReloadConfig();
                    this.props.addNotification(
                        "warning",
                        _("Successfully updated server configuration.  These changes require the server to be restarted to take effect.")
                    );
                })
                .fail(err => {
                    const errMsg = JSON.parse(err);
                    this.handleReloadConfig();
                    this.props.addNotification(
                        "error",
                        cockpit.format(_("Error updating server configuration - $0"), errMsg.desc)
                    );
                });
    }

    handleReloadConfig() {
        const cmd = [
            "dsconf", "-j", "ldapi://%2fvar%2frun%2fslapd-" + this.props.serverId + ".socket",
            "config", "get"
        ];
        log_cmd("handleReloadConfig", "Reload server configuration", cmd);
        cockpit
                .spawn(cmd, { superuser: true, err: "message" })
                .done(content => {
                    const config = JSON.parse(content);
                    const attrs = config.attrs;
                    let listenhost = "";

                    if ('nsslapd-listenhost' in attrs) {
                        listenhost = attrs['nsslapd-listenhost'][0];
                    }
                    this.setState(() => (
                        {
                            configReloading: false,
                            configSaveDisabled: true,
                            errObjConfig: {},
                            errObjRootDN: {},
                            errObjDiskMon: {},
                            errObjAdv: {},
                            'nsslapd-port': attrs['nsslapd-port'][0],
                            'nsslapd-secureport': attrs['nsslapd-secureport'][0],
                            'nsslapd-localhost': attrs['nsslapd-localhost'][0],
                            'nsslapd-listenhost': listenhost,
                            'nsslapd-bakdir': attrs['nsslapd-bakdir'][0],
                            'nsslapd-ldifdir': attrs['nsslapd-ldifdir'][0],
                            'nsslapd-schemadir': attrs['nsslapd-schemadir'][0],
                            'nsslapd-certdir': attrs['nsslapd-certdir'][0],
                            // Record original values
                            '_nsslapd-port': attrs['nsslapd-port'][0],
                            '_nsslapd-secureport': attrs['nsslapd-secureport'][0],
                            '_nsslapd-localhost': attrs['nsslapd-localhost'][0],
                            '_nsslapd-listenhost': listenhost,
                            '_nsslapd-bakdir': attrs['nsslapd-bakdir'][0],
                            '_nsslapd-ldifdir': attrs['nsslapd-ldifdir'][0],
                            '_nsslapd-schemadir': attrs['nsslapd-schemadir'][0],
                            '_nsslapd-certdir': attrs['nsslapd-certdir'][0],
                        })
                    );
                })
                .fail(err => {
                    const errMsg = JSON.parse(err);
                    this.props.addNotification(
                        "error",
                        cockpit.format(_("Error reloading server configuration - $0"), errMsg.desc)
                    );
                    this.setState({
                        configReloading: false,
                    });
                });
    }

    render() {
        let body = "";
        let diskMonitor = "";

        let saveBtnName = _("Save Settings");
        const extraPrimaryProps = {};
        if (this.state.configReloading || this.state.rootDNReloading ||
            this.state.diskMonReloading || this.state.advReloading) {
            saveBtnName = _("Saving settings ...");
            extraPrimaryProps.spinnerAriaValueText = _("Saving");
        }

        if (this.state['nsslapd-disk-monitoring']) {
            diskMonitor = (
                <Form isHorizontal autoComplete="off" className="ds-margin-top-lg ds-left-indent-lg ds-margin-bottom">
                    <Grid
                        title={_("The available disk space, in bytes, that will trigger the shutdown process. Default is 2mb. Once below half of the threshold then we enter the shutdown mode. Value range: 4096 - 9223372036854775807. (nsslapd-disk-monitoring-threshold)")}
                    >
                        <GridItem className="ds-label" span={3}>
                            {_("Disk Monitoring Threshold")}
                        </GridItem>
                        <GridItem span={9}>
                            <NumberInput
                                value={this.state['nsslapd-disk-monitoring-threshold']}
                                min={4096}
                                max={922337203685477}
                                onMinus={() => { this.onMinusConfig("nsslapd-disk-monitoring-threshold", "diskmon") }}
                                onChange={(e) => { this.onConfigChange(e, "nsslapd-disk-monitoring-threshold", 1, 922337203685477, "diskmon") }}
                                onPlus={() => { this.onPlusConfig("nsslapd-disk-monitoring-threshold", "diskmon") }}
                                inputName="input"
                                inputAriaLabel="number input"
                                minusBtnAriaLabel="minus"
                                plusBtnAriaLabel="plus"
                                widthChars={8}
                            />
                            <FormHelperText  >
                                {_("Value must be greater than or equal to 4096")}
                            </FormHelperText>
                        </GridItem>
                    </Grid>
                    <Grid
                        title={_("How many minutes to wait to allow an admin to clean up disk space before shutting slapd down. The default is 60 minutes. (nsslapd-disk-monitoring-grace-period)")}
                    >
                        <GridItem className="ds-label" span={3}>
                            {_("Disk Monitoring Grace Period")}
                        </GridItem>
                        <GridItem span={9}>
                            <NumberInput
                                value={this.state['nsslapd-disk-monitoring-grace-period']}
                                min={1}
                                max={2147483647}
                                onMinus={() => { this.onMinusConfig("nsslapd-disk-monitoring-grace-period", "diskmon") }}
                                onChange={(e) => { this.onConfigChange(e, "nsslapd-disk-monitoring-grace-period", 1, 2147483647, "diskmon") }}
                                onPlus={() => { this.onPlusConfig("nsslapd-disk-monitoring-grace-period", "diskmon") }}
                                inputName="input"
                                inputAriaLabel="number input"
                                minusBtnAriaLabel="minus"
                                plusBtnAriaLabel="plus"
                                widthChars={8}
                            />
                        </GridItem>
                    </Grid>
                    <Grid
                        className="ds-margin-top"
                        title={_("When disk space gets critically low do not remove logs to free up disk space. (nsslapd-disk-monitoring-logging-critical)")}
                    >
                        <GridItem span={9}>
                            <Checkbox
                                id="nsslapd-disk-monitoring-logging-critical"
                                isChecked={this.state['nsslapd-disk-monitoring-logging-critical']}
                                onChange={(e, str) => {
                                    this.handleChange(e, "diskmon");
                                }}
                                label={_("Preserve Logs Even If Disk Space Gets Low")}
                            />
                        </GridItem>
                    </Grid>
                </Form>
            );
        }

        if (this.state.loading) {
            body = (
                <div className="ds-loading-spinner ds-margin-top ds-center">
                    <TextContent>
                        <Text component={TextVariants.h3}>_("Loading Server Settings ...")</Text>
                    </TextContent>
                    <Spinner className="ds-margin-top" size="md" />
                </div>
            );
        } else {
            body = (
                <div className="ds-margin-bottom-md">
                    <Grid>
                        <GridItem span={12}>
                            <TextContent>
                                <Text component={TextVariants.h3}>
                                    {_("Server Settings")}
                                    <Button 
                                        variant="plain"
                                        aria-label={_("Refresh configuration settings")}
                                        onClick={this.handleReloadConfig}
                                    >
                                        <SyncAltIcon size="lg" />
                                    </Button>
                                </Text>
                            </TextContent>
                        </GridItem>
                    </Grid>

                    <div className={this.state.loading ? 'ds-fadeout' : 'ds-fadein ds-left-margin'}>
                        <Tabs isFilled className="ds-margin-top-lg" activeKey={this.state.activeTabKey} onSelect={this.handleNavSelect}>
                            <Tab eventKey={0} title={<TabTitleText>{_("General Settings")}</TabTitleText>}>
                                <Form autoComplete="off" className="ds-margin-top-xlg">
                                    <Grid
                                        title={_("The version of the Directory Server package")}
                                    >
                                        <GridItem className="ds-label" span={2}>
                                            {_("Server Version")}
                                        </GridItem>
                                        <GridItem span={10}>
                                            <TextInput
                                                value={this.props.version}
                                                type="text"
                                                id="server-version"
                                                aria-describedby="horizontal-form-name-helper"
                                                name="server-version"
                                                isDisabled
                                            />
                                        </GridItem>
                                    </Grid>
                                    <Grid
                                        title={_("The server's local hostname (nsslapd-localhost).")}
                                    >
                                        <GridItem className="ds-label" span={2}>
                                            {_("Server Hostname")}
                                        </GridItem>
                                        <GridItem span={10}>
                                            <TextInput
                                                value={this.state['nsslapd-localhost']}
                                                type="text"
                                                id="nsslapd-localhost"
                                                aria-describedby="horizontal-form-name-helper"
                                                name="server-hostname"
                                                onChange={(e, str) => {
                                                    this.handleChange(e, "config");
                                                }}
                                                validated={this.state.errObjConfig['nsslapd-localhost'] ? ValidatedOptions.error : ValidatedOptions.default}
                                            />
                                        </GridItem>
                                    </Grid>
                                    <Grid
                                        title={_("The server's port number (nsslapd-port).")}
                                    >
                                        <GridItem className="ds-label" span={2}>
                                            {_("LDAP Port")}
                                        </GridItem>
                                        <GridItem span={10}>
                                            <NumberInput
                                                value={this.state['nsslapd-port']}
                                                min={1}
                                                max={65534}
                                                onMinus={() => { this.onMinusConfig("nsslapd-port", "config") }}
                                                onChange={(e) => { this.onConfigChange(e, "nsslapd-port", 1, 65534, "config") }}
                                                onPlus={() => { this.onPlusConfig("nsslapd-port", "config") }}
                                                inputName="input"
                                                inputAriaLabel="number input"
                                                minusBtnAriaLabel="minus"
                                                plusBtnAriaLabel="plus"
                                                widthChars={8}
                                                validated={this.state.errObjConfig['nsslapd-port'] ? ValidatedOptions.error : ValidatedOptions.default}
                                            />
                                        </GridItem>
                                    </Grid>
                                    <Grid
                                        title={_("The server's secure port number (nsslapd-secureport).")}
                                    >
                                        <GridItem className="ds-label" span={2}>
                                            {_("LDAPS Port")}
                                        </GridItem>
                                        <GridItem span={10}>
                                            <NumberInput
                                                value={this.state['nsslapd-secureport']}
                                                min={1}
                                                max={65534}
                                                onMinus={() => { this.onMinusConfig("nsslapd-secureport", "config") }}
                                                onChange={(e) => { this.onConfigChange(e, "nsslapd-secureport", 1, 65534, "config") }}
                                                onPlus={() => { this.onPlusConfig("nsslapd-secureport", "config") }}
                                                inputName="input"
                                                inputAriaLabel="number input"
                                                minusBtnAriaLabel="minus"
                                                plusBtnAriaLabel="plus"
                                                widthChars={8}
                                                validated={this.state.errObjConfig['nsslapd-secureport'] ? ValidatedOptions.error : ValidatedOptions.default}
                                            />
                                        </GridItem>
                                    </Grid>
                                    <Grid
                                        title={_("This parameter can be used to restrict the Directory Server instance to a single IP interface (hostname, or IP address).  Requires restart. (nsslapd-listenhost).")}
                                    >
                                        <GridItem className="ds-label" span={2}>
                                            {_("Listen Host Address")}
                                        </GridItem>
                                        <GridItem span={10}>
                                            <TextInput
                                                value={this.state['nsslapd-listenhost']}
                                                type="text"
                                                id="nsslapd-listenhost"
                                                aria-describedby="horizontal-form-name-helper"
                                                name="server-listenhost"
                                                onChange={(e, str) => {
                                                    this.handleChange(e, "config");
                                                }}
                                                validated={this.state.errObjConfig['nsslapd-listenhost'] ? ValidatedOptions.error : ValidatedOptions.default}
                                            />
                                        </GridItem>
                                    </Grid>
                                    <Grid
                                        title={this.state.errObjConfig['nsslapd-bakdir'] ? _("Invalid backup directory path!") : _("The location where database backups are stored (nsslapd-bakdir).")}
                                    >
                                        <GridItem className="ds-label" span={2}>
                                            {_("Backup Directory")}
                                        </GridItem>
                                        <GridItem span={10}>
                                            <TextInput
                                                value={this.state['nsslapd-bakdir']}
                                                type="text"
                                                id="nsslapd-bakdir"
                                                aria-describedby="horizontal-form-name-helper"
                                                name="server-bakdir"
                                                onChange={(e, str) => {
                                                    this.handleChange(e, "config");
                                                }}
                                                validated={this.state.errObjConfig['nsslapd-bakdir'] ? ValidatedOptions.error : ValidatedOptions.default}
                                            />
                                            {this.state.errObjConfig['nsslapd-bakdir'] &&
                                                <FormHelperText  >
                                                    Invalid path
                                                </FormHelperText>}
                                        </GridItem>
                                    </Grid>
                                    <Grid
                                        title={this.state.errObjConfig['nsslapd-ldifdir'] ? _("Invalid LDIF directory path!") : _("The location where the server's LDIF files are located (nsslapd-ldifdir).")}
                                    >
                                        <GridItem className="ds-label" span={2}>
                                            {_("LDIF File Directory")}
                                        </GridItem>
                                        <GridItem span={10}>
                                            <TextInput
                                                value={this.state['nsslapd-ldifdir']}
                                                type="text"
                                                id="nsslapd-ldifdir"
                                                aria-describedby="horizontal-form-name-helper"
                                                name="server-ldifdir"
                                                onChange={(e, str) => {
                                                    this.handleChange(e, "config");
                                                }}
                                                validated={this.state.errObjConfig['nsslapd-ldifdir'] ? ValidatedOptions.error : ValidatedOptions.default}
                                            />
                                            {this.state.errObjConfig['nsslapd-ldifdir'] &&
                                                <FormHelperText  >
                                                    Invalid path
                                                </FormHelperText>}
                                        </GridItem>
                                    </Grid>
                                    <Grid
                                        title={this.state.errObjConfig['nsslapd-schemadir'] ? _("Invalid schema directory path!") : _("The location for the servers custom schema files. (nsslapd-schemadir).")}
                                    >
                                        <GridItem className="ds-label" span={2}>
                                            {_("Schema Directory")}
                                        </GridItem>
                                        <GridItem span={10}>
                                            <TextInput
                                                value={this.state['nsslapd-schemadir']}
                                                type="text"
                                                id="nsslapd-schemadir"
                                                aria-describedby="horizontal-form-name-helper"
                                                name="server-schemadir"
                                                onChange={(e, str) => {
                                                    this.handleChange(e, "config");
                                                }}
                                                validated={this.state.errObjConfig['nsslapd-schemadir'] ? ValidatedOptions.error : ValidatedOptions.default}
                                            />
                                            {this.state.errObjConfig['nsslapd-schemadir'] &&
                                                <FormHelperText  >
                                                    Invalid path
                                                </FormHelperText>}
                                        </GridItem>
                                    </Grid>
                                    <Grid
                                        title={this.state.errObjConfig['nsslapd-certdir'] ? _("Invalid certificate directory path!") : _("The location of the server's certificates (nsslapd-certdir).")}
                                    >
                                        <GridItem className="ds-label" span={2}>
                                            {_("Certificate Directory")}
                                        </GridItem>
                                        <GridItem span={10}>
                                            <TextInput
                                                value={this.state['nsslapd-certdir']}
                                                type="text"
                                                id="nsslapd-certdir"
                                                aria-describedby="horizontal-form-name-helper"
                                                name="server-certdir"
                                                onChange={(e, str) => {
                                                    this.handleChange(e, "config");
                                                }}
                                                validated={this.state.errObjConfig['nsslapd-certdir'] ? ValidatedOptions.error : ValidatedOptions.default}
                                            />
                                            {this.state.errObjConfig['nsslapd-certdir'] &&
                                                <FormHelperText  >
                                                    Invalid path
                                                </FormHelperText>}
                                        </GridItem>
                                    </Grid>
                                </Form>
                                <Button
                                    isDisabled={this.state.configSaveDisabled || this.state.configReloading}
                                    variant="primary"
                                    className="ds-margin-top-xlg"
                                    onClick={this.handleSaveConfig}
                                    isLoading={this.state.configReloading}
                                    spinnerAriaValueText={this.state.configReloading ? _("Saving") : undefined}
                                    {...extraPrimaryProps}
                                >
                                    {saveBtnName}
                                </Button>
                            </Tab>

                            <Tab eventKey={1} title={<TabTitleText>{_("Directory Manager")}</TabTitleText>}>
                                <Form className="ds-margin-top-xlg" isHorizontal autoComplete="off">
                                    <Grid
                                        title={_("The DN of the unrestricted directory manager (nsslapd-rootdn).")}
                                    >
                                        <GridItem className="ds-label" span={3}>
                                            {_("Directory Manager DN")}
                                        </GridItem>
                                        <GridItem span={9}>
                                            <TextInput
                                                value={this.state['nsslapd-rootdn']}
                                                type="text"
                                                id="nsslapd-rootdn"
                                                aria-describedby="horizontal-form-name-helper"
                                                name="nsslapd-rootdn"
                                                isDisabled
                                            />
                                        </GridItem>
                                    </Grid>
                                    <Grid
                                        title={_("The password for the Root DN/Directory Manager (nsslapd-rootpw).")}
                                    >
                                        <GridItem className="ds-label" span={3}>
                                            {_("Directory Manager Password")}
                                        </GridItem>
                                        <GridItem span={9}>
                                            <TextInput
                                                value={this.state['nsslapd-rootpw']}
                                                type="password"
                                                id="nsslapd-rootpw"
                                                aria-describedby="horizontal-form-name-helper"
                                                name="nsslapd-rootpw"
                                                onChange={(e, str) => {
                                                    this.handleChange(e, "rootdn");
                                                }}
                                                validated={this.state.errObjRootDN['nsslapd-rootpw'] ? ValidatedOptions.error : ValidatedOptions.default}
                                            />
                                        </GridItem>
                                    </Grid>
                                    <Grid
                                        title={_("Confirm the Directory Manager password")}
                                    >
                                        <GridItem className="ds-label" span={3}>
                                            {_("Confirm Password")}
                                        </GridItem>
                                        <GridItem span={9}>
                                            <TextInput
                                                value={this.state.confirmRootpw}
                                                type="password"
                                                id="confirmRootpw"
                                                aria-describedby="horizontal-form-name-helper"
                                                name="confirmRootpw"
                                                onChange={(e, str) => {
                                                    this.handleChange(e, "rootdn");
                                                }}
                                                validated={this.state.errObjRootDN.confirmRootpw ? ValidatedOptions.error : ValidatedOptions.default}
                                            />
                                        </GridItem>
                                    </Grid>
                                    <Grid
                                        title={_("Set the Directory Manager password storage scheme (nsslapd-rootpwstoragescheme).")}
                                    >
                                        <GridItem className="ds-label" span={3}>
                                            {_("Password Storage Scheme")}
                                        </GridItem>
                                        <GridItem span={9}>
                                            <FormSelect
                                                id="nsslapd-rootpwstoragescheme"
                                                value={this.state['nsslapd-rootpwstoragescheme']}
                                                onChange={(e, str) => {
                                                    this.handleChange(e, "rootdn");
                                                }}
                                                aria-label="FormSelect Input"
                                            >
                                                {this.options.map((option, index) => (
                                                    <FormSelectOption key={index} value={option.value} label={option.label} />
                                                ))}
                                            </FormSelect>
                                        </GridItem>
                                    </Grid>
                                </Form>
                                <Button
                                    variant="primary"
                                    className="ds-margin-top-xlg"
                                    isDisabled={this.state.rootDNSaveDisabled || this.state.rootDNReloading}
                                    onClick={this.handleSaveRootDN}
                                    isLoading={this.state.rootDNReloading}
                                    spinnerAriaValueText={this.state.rootDNReloading ? _("Saving") : undefined}
                                    {...extraPrimaryProps}
                                >
                                    {saveBtnName}
                                </Button>
                            </Tab>
                            <Tab eventKey={2} title={<TabTitleText>{_("Disk Monitoring")}</TabTitleText>}>
                                <Form className="ds-margin-left ds-margin-top-xlg" autoComplete="off">
                                    <Checkbox
                                        id="nsslapd-disk-monitoring"
                                        isChecked={this.state['nsslapd-disk-monitoring']}
                                        onChange={(e, str) => {
                                            this.handleChange(e, "diskmon");
                                        }}
                                        label={_("Enable Disk Space Monitoring")}
                                    />
                                </Form>
                                {diskMonitor}
                                <Button
                                    isDisabled={this.state.diskMonSaveDisabled || this.state.diskMonReloading}
                                    variant="primary"
                                    className="ds-margin-top-xlg"
                                    onClick={this.handleSaveDiskMonitoring}
                                    isLoading={this.state.diskMonReloading}
                                    spinnerAriaValueText={this.state.diskMonReloading ? _("Saving") : undefined}
                                    {...extraPrimaryProps}
                                >
                                    {saveBtnName}
                                </Button>
                            </Tab>
                            <Tab eventKey={3} title={<TabTitleText>{_("Advanced Settings")}</TabTitleText>}>
                                <Form className="ds-margin-top-xlg ds-margin-left" isHorizontal autoComplete="off">
                                    <Grid>
                                        <GridItem span={5}>
                                            <Checkbox
                                                id="nsslapd-schemacheck"
                                                isChecked={this.state['nsslapd-schemacheck']}
                                                onChange={(e, str) => {
                                                    this.handleChange(e, "adv");
                                                }}
                                                title={_("Enable schema checking (nsslapd-schemacheck).")}
                                                aria-label="uncontrolled checkbox example"
                                                label={_("Enable Schema Checking")}
                                            />
                                        </GridItem>
                                        <GridItem span={5}>
                                            <Checkbox
                                                id="nsslapd-syntaxcheck"
                                                isChecked={this.state['nsslapd-syntaxcheck']}
                                                onChange={(e, str) => {
                                                    this.handleChange(e, "adv");
                                                }}
                                                title={_("Enable attribute syntax checking (nsslapd-syntaxcheck).")}
                                                label={_("Enable Attribute Syntax Checking")}
                                            />
                                        </GridItem>
                                    </Grid>
                                    <Grid>
                                        <GridItem span={5}>
                                            <Checkbox
                                                id="nsslapd-plugin-logging"
                                                isChecked={this.state['nsslapd-plugin-logging']}
                                                onChange={(e, str) => {
                                                    this.handleChange(e, "adv");
                                                }}
                                                title={_("Enable plugins to log access and audit events.  (nsslapd-plugin-logging).")}
                                                label={_("Enable Plugin Logging")}
                                            />
                                        </GridItem>
                                        <GridItem span={5}>
                                            <Checkbox
                                                id="nsslapd-syntaxlogging"
                                                isChecked={this.state['nsslapd-syntaxlogging']}
                                                onChange={(e, str) => {
                                                    this.handleChange(e, "adv");
                                                }}
                                                title={_("Enable syntax logging (nsslapd-syntaxlogging).")}
                                                label={_("Enable Attribute Syntax Logging")}
                                            />
                                        </GridItem>
                                    </Grid>
                                    <Grid>
                                        <GridItem span={5}>
                                            <Checkbox
                                                id="nsslapd-plugin-binddn-tracking"
                                                isChecked={this.state['nsslapd-plugin-binddn-tracking']}
                                                onChange={(e, str) => {
                                                    this.handleChange(e, "adv");
                                                }}
                                                label={_("Enable Plugin Bind DN Tracking")}
                                                title={_("Enabling this feature will write new operational attributes to the modified entry: internalModifiersname & internalCreatorsname. These new attributes contain the plugin DN, while modifiersname will be the original binding entry that triggered the update. (nsslapd-plugin-binddn-tracking).")}
                                            />
                                        </GridItem>
                                        <GridItem span={5}>
                                            <Checkbox
                                                id="nsslapd-attribute-name-exceptions"
                                                isChecked={this.state['nsslapd-attribute-name-exceptions']}
                                                onChange={(e, str) => {
                                                    this.handleChange(e, "adv");
                                                }}
                                                title={_("Allows non-standard characters in attribute names to be used for backwards compatibility with older servers (nsslapd-attribute-name-exceptions).")}
                                                label={_("Allow Attribute Naming Exceptions")}
                                            />
                                        </GridItem>
                                    </Grid>
                                    <Grid>
                                        <GridItem span={5}>
                                            <Checkbox
                                                id="nsslapd-dn-validate-strict"
                                                isChecked={this.state['nsslapd-dn-validate-strict']}
                                                onChange={(e, str) => {
                                                    this.handleChange(e, "adv");
                                                }}
                                                label={_("Strict DN Syntax Validation")}
                                                title={_("Enables strict syntax validation for DNs, according to section 3 in RFC 4514 (nsslapd-dn-validate-strict).")}
                                            />
                                        </GridItem>
                                        <GridItem span={5}>
                                            <Checkbox
                                                id="nsslapd-entryusn-global"
                                                isChecked={this.state['nsslapd-entryusn-global']}
                                                onChange={(e, str) => {
                                                    this.handleChange(e, "adv");
                                                }}
                                                title={_("For USN plugin - maintain unique USNs across all back end databases (nsslapd-entryusn-global).")}
                                                label={_("Maintain Unique USNs Across All Backends")}
                                            />
                                        </GridItem>
                                    </Grid>
                                    <Grid>
                                        <GridItem span={5}>
                                            <Checkbox
                                                id="nsslapd-ignore-time-skew"
                                                isChecked={this.state['nsslapd-ignore-time-skew']}
                                                onChange={(e, str) => {
                                                    this.handleChange(e, "adv");
                                                }}
                                                title={_("Ignore replication time skew when acquiring a replica to start a replciation session (nsslapd-ignore-time-skew).")}
                                                label={_("Ignore CSN Time Skew")}
                                            />
                                        </GridItem>
                                        <GridItem span={5}>
                                            <Checkbox
                                                id="nsslapd-readonly"
                                                isChecked={this.state['nsslapd-readonly']}
                                                onChange={(e, str) => {
                                                    this.handleChange(e, "adv");
                                                }}
                                                title={_("Make entire server read-only (nsslapd-readonly)")}
                                                label={_("Server Read-Only")}
                                            />
                                        </GridItem>
                                    </Grid>
                                    <Grid
                                        className="ds-margin-top"
                                        title={_("Allow anonymous binds to the server (nsslapd-allow-anonymous-access).")}
                                    >
                                        <GridItem className="ds-label" span={3}>
                                            {_("Allow Anonymous Access")}
                                        </GridItem>
                                        <GridItem span={9}>
                                            <FormSelect
                                                id="nsslapd-allow-anonymous-access"
                                                value={this.state['nsslapd-allow-anonymous-access']}
                                                onChange={(e, str) => {
                                                    this.handleChange(e, "adv");
                                                }}
                                                aria-label="FormSelect Input"
                                            >
                                                <FormSelectOption key="0" value="on" label="on" />
                                                <FormSelectOption key="1" value="off" label="off" />
                                                <FormSelectOption
                                                    key="2"
                                                    value="rootdse"
                                                    label="rootdse"
                                                    title={_("Allows anonymous search and read access to search the root DSE itself, but restricts access to all other directory entries. ")}
                                                />
                                            </FormSelect>
                                        </GridItem>
                                    </Grid>
                                    <Grid
                                        title={_("The DN of a template entry containing the resource limits to apply to anonymous connections (nsslapd-anonlimitsdn).")}
                                    >
                                        <GridItem className="ds-label" span={3}>
                                            {_("Anonymous Resource Limits DN")}
                                        </GridItem>
                                        <GridItem span={9}>
                                            <TextInput
                                                value={this.state['nsslapd-anonlimitsdn']}
                                                type="text"
                                                id="nsslapd-anonlimitsdn"
                                                aria-describedby="horizontal-form-name-helper"
                                                name="nsslapd-anonlimitsdn"
                                                onChange={(e, str) => {
                                                    this.handleChange(e, "adv");
                                                }}
                                                validated={this.state.errObjAdv.anonLimitsDN ? ValidatedOptions.error : ValidatedOptions.default}
                                            />
                                        </GridItem>
                                    </Grid>
                                    <Grid
                                        title="HAProxy header is only checked if this setting (nsslapd-haproxy-trusted-ip) is configured. It should have a list of trusted HAProxy server IPs"
                                    >
                                        <GridItem className="ds-label" span={3}>
                                            Trusted HAProxy Server IPs
                                        </GridItem>
                                        <GridItem span={9}>
                                            <Select
                                                variant={SelectVariant.typeaheadMulti}
                                                id="nsslpad-haproxy-trusted-ip"
                                                typeAheadAriaLabel="Type trusted HAProxy server IP address"
                                                onToggle={(event, isOpen) => this.handleOnHaproxyIPsToggle(event, isOpen)}
                                                onSelect={(e, selection) => {
                                                    this.handleOnHaproxyIPsSelect(e, selection, "adv");
                                                }}
                                                onClear={(e) => {
                                                    this.handleOnHaproxyIPsClear(e, "adv");
                                                }}
                                                selections={this.state.haproxyIPs}
                                                isOpen={this.state.isHaproxyIPsOpen}
                                                aria-labelledby="typeAhead-haproxy-ips"
                                                placeholderText="Type trusted HAProxy server IP address"
                                                isCreatable
                                                onCreateOption={this.handleOnCreateHaproxyIP}
                                                validated={this.state.invalidIP ? ValidatedOptions.error : ValidatedOptions.default}
                                            >
                                                {[].map((attr, index) => (
                                                    <SelectOption
                                                        key={index}
                                                        value={attr}
                                                    />
                                                ))}
                                            </Select>
                                            {(this.state.invalidIP) &&
                                                <HelperText className="ds-left-margin">
                                                    <HelperTextItem variant="error">Invalid format for IP address</HelperTextItem>
                                                </HelperText>}
                                        </GridItem>
                                    </Grid>
                                </Form>
                                <Button
                                    isDisabled={this.state.advSaveDisabled || this.state.advReloading}
                                    variant="primary"
                                    className="ds-margin-top-xlg"
                                    onClick={this.handleSaveAdvanced}
                                    isLoading={this.state.advReloading}
                                    spinnerAriaValueText={this.state.advReloading ? _("Saving") : undefined}
                                    {...extraPrimaryProps}
                                >
                                    {saveBtnName}
                                </Button>
                            </Tab>
                        </Tabs>
                    </div>
                </div>
            );
        }

        return (
            <div
                id="server-settings-page" className={this.state.configReloading || this.state.rootDNReloading ||
                this.state.diskMonReloading || this.state.advReloading
                    ? "ds-disabled"
                    : ""}
            >
                {body}
            </div>
        );
    }
}

// Property types and defaults

ServerSettings.propTypes = {
    addNotification: PropTypes.func,
    serverId: PropTypes.string,
    version: PropTypes.string,
    attrs: PropTypes.object,
};

ServerSettings.defaultProps = {
    serverId: "",
    version: "",
    attrs: {},
};
