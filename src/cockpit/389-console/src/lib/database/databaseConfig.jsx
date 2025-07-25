import cockpit from "cockpit";
import React from "react";
import { log_cmd } from "../tools.jsx";
import {
    Alert,
    Button,
    Checkbox,
    Form,
    Grid,
    GridItem,
    NumberInput,
    Spinner,
    Switch,
    Tab,
    Tabs,
    TabTitleText,
    Text,
    TextContent,
    TextInput,
    TextVariants,
    TimePicker,
    Tooltip,
    ValidatedOptions,
} from "@patternfly/react-core";
import PropTypes from "prop-types";
import { SyncAltIcon } from '@patternfly/react-icons';
import { OutlinedQuestionCircleIcon } from '@patternfly/react-icons/dist/js/icons/outlined-question-circle-icon';

const _ = cockpit.gettext;

export class GlobalDatabaseConfig extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            saving: false,
            saveBtnDisabled: true,
            error: {},
            activeTabKey:  this.props.data.activeTab,
            db_cache_auto: this.props.data.db_cache_auto,
            import_cache_auto: this.props.data.import_cache_auto,
            looklimit: this.props.data.looklimit,
            idscanlimit: this.props.data.idscanlimit,
            pagelooklimit: this.props.data.pagelooklimit,
            pagescanlimit: this.props.data.pagescanlimit,
            rangelooklimit: this.props.data.rangelooklimit,
            autosize: this.props.data.autosize,
            autosizesplit: this.props.data.autosizesplit,
            dbcachesize: this.props.data.dbcachesize,
            txnlogdir: this.props.data.txnlogdir,
            dbhomedir: this.props.data.dbhomedir,
            dblocks: this.props.data.dblocks,
            dblocksMonitoring: this.props.data.dblocksMonitoring,
            dblocksMonitoringThreshold: this.props.data.dblocksMonitoringThreshold,
            dblocksMonitoringPause: this.props.data.dblocksMonitoringPause,
            chxpoint: this.props.data.chxpoint,
            compactinterval: this.props.data.compactinterval,
            compacttime: this.props.data.compacttime,
            importcachesize: this.props.data.importcachesize,
            importcacheauto: this.props.data.importcacheauto,
            ndncachemaxsize: this.props.data.ndncachemaxsize,
            // These variables store the original value (used for saving config)
            _looklimit: this.props.data.looklimit,
            _idscanlimit: this.props.data.idscanlimit,
            _pagelooklimit: this.props.data.pagelooklimit,
            _pagescanlimit: this.props.data.pagescanlimit,
            _rangelooklimit: this.props.data.rangelooklimit,
            _autosize: this.props.data.autosize,
            _autosizesplit: this.props.data.autosizesplit,
            _dbcachesize: this.props.data.dbcachesize,
            _txnlogdir: this.props.data.txnlogdir,
            _dbhomedir: this.props.data.dbhomedir,
            _dblocks: this.props.data.dblocks,
            _dblocksMonitoring: this.props.data.dblocksMonitoring,
            _dblocksMonitoringThreshold: this.props.data.dblocksMonitoringThreshold,
            _dblocksMonitoringPause: this.props.data.dblocksMonitoringPause,
            _chxpoint: this.props.data.chxpoint,
            _compactinterval: this.props.data.compactinterval,
            _compacttime: this.props.data.compacttime,
            _importcachesize: this.props.data.importcachesize,
            _importcacheauto: this.props.data.importcacheauto,
            _db_cache_auto: this.props.data.db_cache_auto,
            _import_cache_auto: this.props.data.import_cache_auto,
            _ndncachemaxsize: this.props.data.ndncachemaxsize,
        };

        this.validateSaveBtn = this.validateSaveBtn.bind(this);
        this.handleChange = this.handleChange.bind(this);
        this.handleTimeChange = this.handleTimeChange.bind(this);
        this.handleSelectDBLocksMonitoring = this.handleSelectDBLocksMonitoring.bind(this);
        this.handleSaveDBConfig = this.handleSaveDBConfig.bind(this);

        this.maxValue = 2147483647;
        this.onMinusConfig = (id) => {
            this.setState({
                [id]: Number(this.state[id]) - 1,
            }, () => { this.validateSaveBtn() });
        };
        this.onConfigChange = (event, id, min, max) => {
            let error = this.state.error;
            let maxValue = this.maxValue;
            if (max !== 0) {
                maxValue = max;
            }
            let badValue = false;
            const newValue = isNaN(event.target.value) ? 0 : Number(event.target.value);
            if (newValue > maxValue || newValue < min) {
                badValue = true;
            }
            error[id] = badValue;
            this.setState({
                [id]: newValue,
                error,
            }, () => { this.validateSaveBtn() });
        };
        this.onPlusConfig = (id) => {
            this.setState({
                [id]: Number(this.state[id]) + 1,
            }, () => { this.validateSaveBtn() });
        };

        // Toggle currently active tab
        this.handleNavSelect = (event, tabIndex) => {
            this.setState({
                activeTabKey: tabIndex
            });
        };
    }

    componentDidMount() {
        this.props.enableTree();
    }

    handleSelectDBLocksMonitoring (e, val) {
        this.setState({
            dblocksMonitoring: !this.state.dblocksMonitoring
        }, this.handleChange(e, val));
    }

    validateSaveBtn() {
        let saveBtnDisabled = true;
        const check_attrs = [
            "db_cache_auto", "import_cache_auto", "looklimit",
            "idscanlimit", "pagelooklimit", "pagescanlimit",
            "rangelooklimit", "autosize", "autosizesplit",
            "dbcachesize", "txnlogdir", "dbhomedir",
            "dblocks", "dblocksMonitoring", "dblocksMonitoringThreshold",
            "dblocksMonitoringPause", "chxpoint", "compactinterval",
            "compacttime", "importcachesize", "importcacheauto",
            "ndncachemaxsize",
        ];

        // Check if a setting was changed, if so enable the save button
        for (const config_attr of check_attrs) {
            if (this.state[config_attr] !== this.state['_' + config_attr]) {
                saveBtnDisabled = false;
                break;
            }
        }

        // Check if have any errors on our attributes
        for (const config_attr of check_attrs) {
            if (config_attr in this.state.error && this.state.error[config_attr]) {
                saveBtnDisabled = true;
                break;
            }
        }

        this.setState({
            saveBtnDisabled,
        });
    }

    handleChange(e, str) {
        // Generic
        const value = e.target.type === 'checkbox' ? e.target.checked : e.target.value;
        const attr = e.target.id;

        if (attr === "import_cache_auto" && value) {
            // We need to set it to -1 if it's already set to 0
            if (this.state.importcacheauto === "0") {
                this.setState({ importcacheauto: "-1" });
            }
        }

        this.setState({
            [attr]: value,
        }, () => { this.validateSaveBtn() });
    }

    handleTimeChange = (_event, time, hour, min, seconds, isValid) => {
        this.setState({
            compacttime: time,
        }, () => { this.validateSaveBtn() });
    }

    save_ndn_cache(requireRestart) {
        const msg = "Successfully updated database configuration";
        if (this.state._ndncachemaxsize !== this.state.ndncachemaxsize) {
            const cmd = [
                'dsconf', '-j', 'ldapi://%2fvar%2frun%2fslapd-' + this.props.serverId + '.socket',
                'config', 'replace', 'nsslapd-ndn-cache-max-size=' + this.state.ndncachemaxsize
            ];

            log_cmd("save_ndn_cache", "Applying config change", cmd);
            cockpit
                    .spawn(cmd, { superuser: true, err: "message" })
                    .done(content => {
                        this.props.reload(this.state.activeTabKey);
                        this.setState({
                            saving: false
                        });
                        if (requireRestart) {
                            this.props.addNotification(
                                "warning",
                                cockpit.format(_("$0. You must restart the Directory Server for these changes to take effect."), msg)
                            );
                        } else {
                            this.props.addNotification(
                                "success",
                                msg
                            );
                        }
                    })
                    .fail(err => {
                        const errMsg = JSON.parse(err);
                        this.props.reload(this.state.activeTabKey);
                        this.setState({
                            saving: false
                        });
                        this.props.addNotification(
                            "error",
                            cockpit.format(_("Error updating configuration - $0"), errMsg.desc)
                        );
                    });
        } else {
            this.props.reload(this.state.activeTabKey);
            this.setState({
                saving: false
            });
            if (requireRestart) {
                this.props.addNotification(
                    "warning",
                    cockpit.format(_("$0. You must restart the Directory Server for these changes to take effect."), msg)
                );
            } else {
                this.props.addNotification(
                    "success",
                    msg
                );
            }
        }
    }

    handleSaveDBConfig() {
        // Build up the command list
        const cmd = [
            'dsconf', '-j', 'ldapi://%2fvar%2frun%2fslapd-' + this.props.serverId + '.socket',
            'backend', 'config', 'set'
        ];
        let requireRestart = false;

        if (this.state._looklimit !== this.state.looklimit) {
            cmd.push("--lookthroughlimit=" + this.state.looklimit);
        }
        if (this.state._idscanlimit !== this.state.idscanlimit) {
            cmd.push("--idlistscanlimit=" + this.state.idscanlimit);
        }
        if (this.state._pagelooklimit !== this.state.pagelooklimit) {
            cmd.push("--pagedlookthroughlimit=" + this.state.pagelooklimit);
        }
        if (this.state._pagescanlimit !== this.state.pagescanlimit) {
            cmd.push("--pagedidlistscanlimit=" + this.state.pagescanlimit);
        }
        if (this.state._rangelooklimit !== this.state.rangelooklimit) {
            cmd.push("--rangelookthroughlimit=" + this.state.rangelooklimit);
        }
        if (this.state.db_cache_auto) {
            // Auto cache is selected
            if (this.state._db_cache_auto !== this.state.db_cache_auto) {
                // We just enabled auto cache,
                if (this.state.autosize === "0") {
                    cmd.push("--cache-autosize=10");
                } else {
                    cmd.push("--cache-autosize=" + this.state.autosize);
                }
                requireRestart = true;
            } else if (this.state._autosize !== this.state.autosize) {
                // Update auto cache settings if it changed
                cmd.push("--cache-autosize=" + this.state.autosize);
                requireRestart = true;
            }
        } else {
            // No auto cache, check if we need to reset the value
            if (this.state._db_cache_auto !== this.state.db_cache_auto) {
                // We just disabled auto cache
                cmd.push("--cache-autosize=0");
                requireRestart = true;
            }
        }
        if (this.state._autosizesplit !== this.state.autosizesplit) {
            cmd.push("--cache-autosize-split=" + this.state.autosizesplit);
            requireRestart = true;
        }
        if (this.state._dbcachesize !== this.state.dbcachesize) {
            cmd.push("--dbcachesize=" + this.state.dbcachesize);
            requireRestart = true;
        }
        if (this.state._txnlogdir !== this.state.txnlogdir) {
            cmd.push("--logdirectory=" + this.state.txnlogdir);
            requireRestart = true;
        }
        if (this.state._dbhomedir !== this.state.dbhomedir) {
            cmd.push("--db-home-directory=" + this.state.dbhomedir);
            requireRestart = true;
        }
        if (this.state._dblocks !== this.state.dblocks) {
            cmd.push("--locks=" + this.state.dblocks);
            requireRestart = true;
        }
        if (this.state._dblocksMonitoring !== this.state.dblocksMonitoring) {
            if (this.state.dblocksMonitoring) {
                cmd.push("--locks-monitoring-enabled=on");
            } else {
                cmd.push("--locks-monitoring-enabled=off");
            }
            requireRestart = true;
        }
        if (this.state._dblocksMonitoringThreshold !== this.state.dblocksMonitoringThreshold) {
            cmd.push("--locks-monitoring-threshold=" + this.state.dblocksMonitoringThreshold);
            requireRestart = true;
        }
        if (this.state._dblocksMonitoringPause !== this.state.dblocksMonitoringPause) {
            cmd.push("--locks-monitoring-pause=" + this.state.dblocksMonitoringPause);
        }
        if (this.state._chxpoint !== this.state.chxpoint) {
            cmd.push("--checkpoint-interval=" + this.state.chxpoint);
            requireRestart = true;
        }
        if (this.state._compactinterval !== this.state.compactinterval) {
            cmd.push("--compactdb-interval=" + this.state.compactinterval);
            requireRestart = true;
        }
        if (this.state._compacttime !== this.state.compacttime) {
            cmd.push("--compactdb-time=" + this.state.compacttime);
            requireRestart = true;
        }
        if (this.state.import_cache_auto) {
            // Auto cache is selected
            if (this.state._import_cache_auto !== this.state.import_cache_auto) {
                // We just enabled auto cache,
                if (this.state.importcachesize === "0") {
                    cmd.push("--import-cache-autosize=-1");
                } else {
                    cmd.push("--import-cache-autosize=" + this.state.importcacheauto);
                }
            } else if (this.state._importcacheauto !== this.state.importcacheauto) {
                // Update auto cache settings if it changed
                cmd.push("--import-cache-autosize=" + this.state.importcacheauto);
            }
        } else {
            // Auto cache is not selected, check if we need to reset the value
            if (this.state._import_cache_auto !== this.state.import_cache_auto) {
                // We just disabled auto cache
                cmd.push("--import-cache-autosize=0");
            }
        }
        if (this.state._importcachesize !== this.state.importcachesize) {
            cmd.push("--import-cachesize=" + this.state.importcachesize);
        }
        if (cmd.length > 6) {
            this.setState({
                saving: true
            });
            log_cmd("handleSaveDBConfig", "Applying config change", cmd);
            cockpit
                    .spawn(cmd, { superuser: true, err: "message" })
                    .done(content => {
                        // Continue with the next mod
                        this.save_ndn_cache(requireRestart);
                    })
                    .fail(err => {
                        const errMsg = JSON.parse(err);
                        this.props.reload(this.state.activeTabKey);
                        this.setState({
                            saving: false
                        });
                        this.props.addNotification(
                            "error",
                            cockpit.format(_("Error updating configuration - $0"), errMsg.desc)
                        );
                    });
        } else {
            this.setState({
                saving: true
            }, () => { this.save_ndn_cache(requireRestart) });
        }
    }

    render() {
        let db_cache_form;
        let import_cache_form;
        let db_auto_checked = false;
        let import_auto_checked = false;
        let dblocksMonitor = "";
        const dblocksThreshold = this.state.dblocksMonitoringThreshold;
        const dblocksPause = this.state.dblocksMonitoringPause;

        if (this.state.dblocksMonitoring) {
            dblocksMonitor = (
                <div className="ds-margin-left ds-margin-top">
                    <Grid
                        title={_("Sets the DB lock exhaustion value in percentage (valid range is 70-95). If too many locks are acquired, the server will abort the searches while the number of locks are not decreased. It helps to avoid DB corruption and long recovery. (nsslapd-db-locks-monitoring-threshold).")}
                        className="ds-margin-top"
                    >
                        <GridItem className="ds-label" span={3}>
                            {_("DB Locks Threshold Percentage")}
                        </GridItem>
                        <GridItem span={9}>
                            <NumberInput
                                value={dblocksThreshold}
                                min={70}
                                max={95}
                                onMinus={() => { this.onMinusConfig("dblocksMonitoringThreshold") }}
                                onChange={(e) => { this.onConfigChange(e, "dblocksMonitoringThreshold", 70, 95) }}
                                onPlus={() => { this.onPlusConfig("dblocksMonitoringThreshold") }}
                                inputName="input"
                                inputAriaLabel="number input"
                                minusBtnAriaLabel="minus"
                                plusBtnAriaLabel="plus"
                                widthChars={10}
                                unit="%"
                                validated={'dblocksMonitoringThreshold' in this.state.error &&
                                    this.state.error['dblocksMonitoringThreshold']
                                     ? ValidatedOptions.error
                                     : ValidatedOptions.default}
                            />
                        </GridItem>
                    </Grid>
                    <Grid
                        title={_("Sets the amount of time (milliseconds) that the monitoring thread spends waiting between checks. (nsslapd-db-locks-monitoring-pause).")}
                        className="ds-margin-top"
                    >
                        <GridItem className="ds-label" span={3}>
                            {_("DB Locks Pause Milliseconds")}
                        </GridItem>
                        <GridItem span={9}>
                            <NumberInput
                                value={dblocksPause}
                                min={0}
                                max={this.maxValue}
                                onMinus={() => { this.onMinusConfig("dblocksMonitoringPause") }}
                                onChange={(e) => { this.onConfigChange(e, "dblocksMonitoringPause", 0, 0) }}
                                onPlus={() => { this.onPlusConfig("dblocksMonitoringPause") }}
                                inputName="input"
                                inputAriaLabel="number input"
                                minusBtnAriaLabel="minus"
                                plusBtnAriaLabel="plus"
                                widthChars={10}
                                validated={'dblocksMonitoringPause' in this.state.error &&
                                    this.state.error['dblocksMonitoringPause']
                                     ? ValidatedOptions.error
                                     : ValidatedOptions.default}
                            />
                        </GridItem>
                    </Grid>
                </div>
            );
        }

        if (this.state.db_cache_auto) {
            db_cache_form = (
                <div className="ds-margin-left">
                    <Grid
                        title={_("Enable database and entry cache auto-tuning using a percentage of the system's current resources (nsslapd-cache-autosize). If 0 is set, the default value is used instead.")}
                        className="ds-margin-top"
                    >
                        <GridItem className="ds-label" span={3}>
                            {_("Memory Percentage")}
                        </GridItem>
                        <GridItem span={9}>
                            <NumberInput
                                value={this.state.autosize}
                                min={0}
                                max={100}
                                onMinus={() => { this.onMinusConfig("autosize") }}
                                onChange={(e) => { this.onConfigChange(e, "autosize", 0, 100) }}
                                onPlus={() => { this.onPlusConfig("autosize") }}
                                inputName="input"
                                inputAriaLabel="number input"
                                minusBtnAriaLabel="minus"
                                plusBtnAriaLabel="plus"
                                widthChars={4}
                                unit="%"
                                validated={'autosize' in this.state.error &&
                                    this.state.error['autosize']
                                     ? ValidatedOptions.error
                                     : ValidatedOptions.default}
                            />
                        </GridItem>
                    </Grid>
                    <Grid
                        title={_("Sets the percentage of memory that is used for the database cache. The remaining percentage is used for the entry cache (nsslapd-cache-autosize-split). If 0 is set, the default value is used instead.")}
                        className="ds-margin-top"
                    >
                        <GridItem className="ds-label" span={3}>
                            {_("DB Cache Percentage")}
                        </GridItem>
                        <GridItem span={9}>
                            <NumberInput
                                value={this.state.autosizesplit}
                                min={1}
                                max={99}
                                onMinus={() => { this.onMinusConfig("autosizesplit") }}
                                onChange={(e) => { this.onConfigChange(e, "autosizesplit", 1, 99) }}
                                onPlus={() => { this.onPlusConfig("autosizesplit") }}
                                inputName="input"
                                inputAriaLabel="number input"
                                minusBtnAriaLabel="minus"
                                plusBtnAriaLabel="plus"
                                widthChars={4}
                                unit="%"
                                validated={'autosizesplit' in this.state.error &&
                                    this.state.error['autosizesplit']
                                     ? ValidatedOptions.error
                                     : ValidatedOptions.default}
                            />
                        </GridItem>
                    </Grid>
                </div>
            );
            db_auto_checked = true;
        } else {
            db_cache_form = (
                <div className="ds-margin-left">
                    <Grid
                    title={_("Specifies the database index cache size in bytes (nsslapd-dbcachesize).")}
                    className="ds-margin-top"
                    >
                        <GridItem className="ds-label" span={3}>
                            {_("Database Cache Size")}
                        </GridItem>
                        <GridItem span={9}>
                            <NumberInput
                                value={this.state.dbcachesize}
                                min={512000}
                                max={this.maxValue}
                                onMinus={() => { this.onMinusConfig("dbcachesize") }}
                                onChange={(e) => { this.onConfigChange(e, "dbcachesize", 512000, 0) }}
                                onPlus={() => { this.onPlusConfig("dbcachesize") }}
                                inputName="input"
                                inputAriaLabel="number input"
                                minusBtnAriaLabel="minus"
                                plusBtnAriaLabel="plus"
                                widthChars={10}
                                validated={'dbcachesize' in this.state.error &&
                                    this.state.error['dbcachesize']
                                     ? ValidatedOptions.error
                                     : ValidatedOptions.default}
                            />
                        </GridItem>
                    </Grid>
                </div>
            );
            db_auto_checked = false;
        }

        if (this.state.import_cache_auto) {
            import_cache_form = (
                <div id="auto-import-cache-form" className="ds-margin-left">
                    <Grid
                        title={_("Enter '-1' to use 50% of available memory, '0' to disable autotuning, or enter the percentage of available memory to use.  Value range -1 through 100, default is '-1' (nsslapd-import-cache-autosize).")}
                        className="ds-margin-top"
                    >
                        <GridItem className="ds-label" span={3}>
                            {_("Import Cache Autosize")}
                        </GridItem>
                        <GridItem span={9}>
                            <NumberInput
                                value={this.state.importcacheauto}
                                min={-1}
                                max={100}
                                onMinus={() => { this.onMinusConfig("importcacheauto") }}
                                onChange={(e) => { this.onConfigChange(e, "importcacheauto", -1, 100) }}
                                onPlus={() => { this.onPlusConfig("importcacheauto") }}
                                inputName="input"
                                inputAriaLabel="number input"
                                minusBtnAriaLabel="minus"
                                plusBtnAriaLabel="plus"
                                widthChars={4}
                                unit={this.state.importcacheauto > 0 ? "%" : ""}
                                validated={'importcacheauto' in this.state.error &&
                                    this.state.error['importcacheauto']
                                     ? ValidatedOptions.error
                                     : ValidatedOptions.default}
                            />
                        </GridItem>
                    </Grid>
                </div>
            );
            import_auto_checked = true;
        } else {
            import_cache_form = (
                <div className="ds-margin-left">
                    <Grid
                        title={_("The size of the database cache in bytes used in the bulk import process. (nsslapd-import-cachesize).")}
                        className="ds-margin-top"
                    >
                        <GridItem className="ds-label" span={3}>
                            {_("Import Cache Size")}
                        </GridItem>
                        <GridItem span={9}>
                            <NumberInput
                                value={this.state.importcachesize}
                                min={512000}
                                max={this.maxValue}
                                onMinus={() => { this.onMinusConfig("importcachesize") }}
                                onChange={(e) => { this.onConfigChange(e, "importcachesize", 512000, 0) }}
                                onPlus={() => { this.onPlusConfig("importcachesize") }}
                                inputName="input"
                                inputAriaLabel="number input"
                                minusBtnAriaLabel="minus"
                                plusBtnAriaLabel="plus"
                                widthChars={10}
                                validated={'importcachesize' in this.state.error &&
                                    this.state.error['importcachesize']
                                     ? ValidatedOptions.error
                                     : ValidatedOptions.default}
                            />
                        </GridItem>
                    </Grid>
                </div>
            );
            import_auto_checked = false;
        }

        let spinner = "";
        if (this.state.loading) {
            spinner = (
                <div className="ds-loading-spinner ds-margin-top-xlg ds-center">
                    <TextContent>
                        <Text component={TextVariants.h3}>
                            Loading global database configuration ...
                        </Text>
                    </TextContent>
                    <Spinner className="ds-margin-top" loading size="md" />
                </div>
            );
        }

        let saveBtnName = _("Save Config");
        const extraPrimaryProps = {};
        if (this.props.refreshing) {
            saveBtnName = _("Saving config ...");
            extraPrimaryProps.spinnerAriaValueText = _("Saving");
        }

        return (
            <div className={this.state.saving ? "ds-disabled ds-margin-bottom-md" : "ds-margin-bottom-md"} id="db-global-page">
                {spinner}
                <div className={this.state.loading ? 'ds-fadeout' : 'ds-fadein'}>
                    <TextContent>
                        <Text className="ds-config-header" component={TextVariants.h2}>
                            {_("Global Database Configuration")}
                            <Button
                                variant="plain"
                                aria-label={_("Refresh config settings")}
                                onClick={() => {
                                    this.props.reload(this.state.activeTabKey);
                                }}
                            >
                                <SyncAltIcon />
                            </Button>
                        </Text>
                    </TextContent>
                    <div className="ds-margin-top-lg">
                        <Tabs isFilled activeKey={this.state.activeTabKey} onSelect={this.handleNavSelect}>
                            <Tab eventKey={0} title={<TabTitleText>{_("Limits")}</TabTitleText>}>
                                <div className="ds-left-indent-md">
                                    <Grid
                                        title={_("The maximum number of entries that the Directory Server will check when examining candidate entries in response to a search request (nsslapd-lookthrough-limit).")}
                                        className="ds-margin-top-xlg"
                                    >
                                        <GridItem className="ds-label" span={4}>
                                            {_("Database Look Through Limit")}
                                        </GridItem>
                                        <GridItem span={8}>
                                            <NumberInput
                                                value={this.state.looklimit}
                                                min={-1}
                                                max={this.maxValue}
                                                onMinus={() => { this.onMinusConfig("looklimit") }}
                                                onChange={(e) => { this.onConfigChange(e, "looklimit", -1, 0) }}
                                                onPlus={() => { this.onPlusConfig("looklimit") }}
                                                inputName="input"
                                                inputAriaLabel="number input"
                                                minusBtnAriaLabel="minus"
                                                plusBtnAriaLabel="plus"
                                                widthChars={10}
                                                validated={'looklimit' in this.state.error &&
                                                    this.state.error['looklimit']
                                                     ? ValidatedOptions.error
                                                     : ValidatedOptions.default}
                                            />
                                        </GridItem>
                                    </Grid>
                                    <Grid
                                        title={_("The number of entry IDs that are searched during a search operation (nsslapd-idlistscanlimit).")}
                                        className="ds-margin-top"
                                    >
                                        <GridItem className="ds-label" span={4}>
                                            {_("ID List Scan Limit")}
                                        </GridItem>
                                        <GridItem span={8}>
                                            <NumberInput
                                                value={this.state.idscanlimit}
                                                min={100}
                                                max={this.maxValue}
                                                onMinus={() => { this.onMinusConfig("idscanlimit") }}
                                                onChange={(e) => { this.onConfigChange(e, "idscanlimit", 100, 0) }}
                                                onPlus={() => { this.onPlusConfig("idscanlimit") }}
                                                inputName="input"
                                                inputAriaLabel="number input"
                                                minusBtnAriaLabel="minus"
                                                plusBtnAriaLabel="plus"
                                                widthChars={10}
                                                validated={'idscanlimit' in this.state.error &&
                                                    this.state.error['idscanlimit']
                                                     ? ValidatedOptions.error
                                                     : ValidatedOptions.default}
                                            />
                                        </GridItem>
                                    </Grid>
                                    <Grid
                                        title={_("The maximum number of entries that the Directory Server will check when examining candidate entries for a search which uses the simple paged results control (nsslapd-pagedlookthroughlimit).")}
                                        className="ds-margin-top"
                                    >
                                        <GridItem className="ds-label" span={4}>
                                            {_("Paged Search Look Through Limit")}
                                        </GridItem>
                                        <GridItem span={8}>
                                            <NumberInput
                                                value={this.state.pagelooklimit}
                                                min={-1}
                                                max={this.maxValue}
                                                onMinus={() => { this.onMinusConfig("pagelooklimit") }}
                                                onChange={(e) => { this.onConfigChange(e, "pagelooklimit", -1, 0) }}
                                                onPlus={() => { this.onPlusConfig("pagelooklimit") }}
                                                inputName="input"
                                                inputAriaLabel="number input"
                                                minusBtnAriaLabel="minus"
                                                plusBtnAriaLabel="plus"
                                                widthChars={10}
                                                validated={'pagelooklimit' in this.state.error &&
                                                    this.state.error['pagelooklimit']
                                                     ? ValidatedOptions.error
                                                     : ValidatedOptions.default}
                                            />
                                        </GridItem>
                                    </Grid>
                                    <Grid
                                        title={_("The number of entry IDs that are searched, specifically, for a search operation using the simple paged results control (nsslapd-pagedidlistscanlimit).")}
                                        className="ds-margin-top"
                                    >
                                        <GridItem className="ds-label" span={4}>
                                            {_("Paged Search ID List Scan Limit")}
                                        </GridItem>
                                        <GridItem span={8}>
                                            <NumberInput
                                                value={this.state.pagescanlimit}
                                                min={-1}
                                                max={this.maxValue}
                                                onMinus={() => { this.onMinusConfig("pagescanlimit") }}
                                                onChange={(e) => { this.onConfigChange(e, "pagescanlimit", -1, 0) }}
                                                onPlus={() => { this.onPlusConfig("pagescanlimit") }}
                                                inputName="input"
                                                inputAriaLabel="number input"
                                                minusBtnAriaLabel="minus"
                                                plusBtnAriaLabel="plus"
                                                widthChars={10}
                                                validated={'pagescanlimit' in this.state.error &&
                                                    this.state.error['pagescanlimit']
                                                     ? ValidatedOptions.error
                                                     : ValidatedOptions.default}
                                            />
                                        </GridItem>
                                    </Grid>
                                    <Grid
                                        title={_("The maximum number of entries that the Directory Server will check when examining candidate entries in response to a range search request (nsslapd-rangelookthroughlimit).")}
                                        className="ds-margin-top"
                                    >
                                        <GridItem className="ds-label" span={4}>
                                            {_("Range Search Look Through Limit")}
                                        </GridItem>
                                        <GridItem span={8}>
                                            <NumberInput
                                                value={this.state.rangelooklimit}
                                                min={-1}
                                                max={this.maxValue}
                                                onMinus={() => { this.onMinusConfig("rangelooklimit") }}
                                                onChange={(e) => { this.onConfigChange(e, "rangelooklimit", -1, 0) }}
                                                onPlus={() => { this.onPlusConfig("rangelooklimit") }}
                                                inputName="input"
                                                inputAriaLabel="number input"
                                                minusBtnAriaLabel="minus"
                                                plusBtnAriaLabel="plus"
                                                widthChars={10}
                                                validated={'rangelooklimit' in this.state.error &&
                                                    this.state.error['rangelooklimit']
                                                     ? ValidatedOptions.error
                                                     : ValidatedOptions.default}
                                            />
                                        </GridItem>
                                    </Grid>
                                </div>
                            </Tab>

                            <Tab eventKey={1} title={<TabTitleText>{_("Database Cache")}</TabTitleText>}>
                                <div className="ds-left-indent-md">
                                    <Grid className="ds-margin-top-xlg">
                                        <GridItem span={12}>
                                            <Checkbox
                                                label={_("Automatic Cache Tuning")}
                                                onChange={(e, str) => this.handleChange(e, str)}
                                                isChecked={db_auto_checked}
                                                aria-label="uncontrolled checkbox example"
                                                id="db_cache_auto"
                                            />
                                        </GridItem>
                                        <GridItem span={12}>
                                            {db_cache_form}
                                        </GridItem>
                                    </Grid>
                                </div>
                            </Tab>

                            <Tab eventKey={2} title={<TabTitleText>{_("Import Cache")}</TabTitleText>}>
                                <div className="ds-left-indent-md">
                                    <Grid className="ds-margin-top-xlg">
                                        <GridItem span={12}>
                                            <Checkbox
                                                label={_("Automatic Import Cache Tuning")}
                                                title={_("Set import cache to be set automatically")}
                                                onChange={(e, str) => this.handleChange(e, str)}
                                                isChecked={import_auto_checked}
                                                aria-label="uncontrolled checkbox example"
                                                id="import_cache_auto"
                                            />
                                        </GridItem>
                                        <GridItem span={12}>
                                            {import_cache_form}
                                        </GridItem>
                                    </Grid>
                                </div>
                            </Tab>

                            <Tab eventKey={3} title={<TabTitleText>{_("NDN Cache")}</TabTitleText>}>
                                <div className="ds-left-indent-md">
                                    <Grid
                                        title={_("Warning: Normalized DN Cache is disabled")}
                                        className="ds-margin-top-xlg"
                                    >
                                        {this.props.data.ndn_cache_enabled === false && (
                                            <GridItem span={8}>
                                                <Alert
                                                    variant="warning"
                                                    isInline
                                                    title={_("Normalized DN Cache is disabled")}
                                                    className="ds-margin-bottom"
                                                >
                                                    {_("The Normalized DN Cache is currently disabled. To enable it, go to Server Settings → Tuning & Limits and enable 'Normalized DN Cache', then restart the server for the changes to take effect.")}
                                                </Alert>
                                            </GridItem>
                                        )}
                                    </Grid>
                                    <Grid
                                        title={_("Set the maximum size in bytes for the Normalized DN Cache (nsslapd-ndn-cache-max-size).")}
                                        className="ds-margin-top-xlg"
                                    >
                                        <GridItem className="ds-label" span={4}>
                                            {_("Normalized DN Cache Max Size") }
                                        </GridItem>
                                        <GridItem span={8}>
                                            <NumberInput
                                                value={this.state.ndncachemaxsize}
                                                min={1000000}
                                                max={this.maxValue}
                                                onMinus={() => { this.onMinusConfig("ndncachemaxsize") }}
                                                onChange={(e) => { this.onConfigChange(e, "ndncachemaxsize", 1000000, 0) }}
                                                onPlus={() => { this.onPlusConfig("ndncachemaxsize") }}
                                                inputName="input"
                                                inputAriaLabel="number input"
                                                minusBtnAriaLabel="minus"
                                                plusBtnAriaLabel="plus"
                                                widthChars={10}
                                                validated={'ndncachemaxsize' in this.state.error &&
                                                           this.state.error['ndncachemaxsize']
                                                            ? ValidatedOptions.error
                                                            : ValidatedOptions.default}
                                            />
                                        </GridItem>
                                    </Grid>
                                </div>
                            </Tab>

                            <Tab eventKey={4} title={<TabTitleText>{_("Database Locks")}</TabTitleText>}>
                                <div className="ds-left-indent-md">
                                    <Grid
                                        title={_("The number of database locks (nsslapd-db-locks).")}
                                        className="ds-margin-top-xlg"
                                    >
                                        <GridItem className="ds-label" span={2}>
                                            {_("Database Locks")}
                                        </GridItem>
                                        <GridItem span={10}>
                                            <NumberInput
                                                value={this.state.dblocks}
                                                min={10000}
                                                max={this.maxValue}
                                                onMinus={() => { this.onMinusConfig("dblocks") }}
                                                onChange={(e) => { this.onConfigChange(e, "dblocks", 10000, 0) }}
                                                onPlus={() => { this.onPlusConfig("dblocks") }}
                                                inputName="input"
                                                inputAriaLabel="number input"
                                                minusBtnAriaLabel="minus"
                                                plusBtnAriaLabel="plus"
                                                widthChars={10}
                                                validated={'dblocks' in this.state.error &&
                                                    this.state.error['dblocks']
                                                     ? ValidatedOptions.error
                                                     : ValidatedOptions.default}
                                            />
                                        </GridItem>
                                    </Grid>
                                    <Grid className="ds-margin-top-xlg">
                                        <GridItem span={12}>
                                            <div className="ds-inline">
                                                <Checkbox
                                                    label={_("Enable DB Lock Monitoring")}
                                                    id="dblocksMonitoring"
                                                    isChecked={this.state.dblocksMonitoring}
                                                    onChange={(e, val) => this.handleSelectDBLocksMonitoring(e, val)}
                                                    aria-label="uncontrolled checkbox example"
                                                />
                                            </div>
                                            <div className="ds-inline">
                                                <Tooltip
                                                    id="dblockmonitor"
                                                    position="bottom"
                                                    content={
                                                        <div>
                                                            {_("Database lock monitoring checks if the database locks are about to be exhausted, and if they are the server will abort all the current searches in order to prevent database corruption.")}
                                                        </div>
                                                    }
                                                >
                                                    <OutlinedQuestionCircleIcon
                                                        className="ds-left-margin"
                                                    />
                                                </Tooltip>
                                            </div>
                                        </GridItem>
                                        <GridItem span={12}>
                                            {dblocksMonitor}
                                        </GridItem>
                                    </Grid>
                                </div>
                            </Tab>

                            <Tab eventKey={5} title={<TabTitleText>{_("Advanced Settings")}</TabTitleText>}>
                                <div className="ds-left-indent-md">
                                    <Grid
                                        title={_("Database Transaction Log Location (nsslapd-db-logdirectory).")}
                                        className="ds-margin-top-xlg"
                                    >
                                        <GridItem className="ds-label" span={4}>
                                            {_("Transaction Logs Directory")}
                                        </GridItem>
                                        <GridItem span={8}>
                                            <TextInput
                                                value={this.state.txnlogdir}
                                                type="text"
                                                id="txnlogdir"
                                                aria-describedby="txnlogdir"
                                                name="txnlogdir"
                                                onChange={(e, str) => this.handleChange(e, str)}
                                            />
                                        </GridItem>
                                    </Grid>
                                    <Grid
                                        title={_("Location for database memory mapped files.  You must specify a subdirectory of a tempfs type filesystem (nsslapd-db-home-directory).")}
                                        className="ds-margin-top"
                                    >
                                        <GridItem className="ds-label" span={4}>
                                            {_("Database Home Directory")}
                                        </GridItem>
                                        <GridItem span={8}>
                                            <TextInput
                                                value={this.state.dbhomedir}
                                                type="text"
                                                id="dbhomedir"
                                                aria-describedby="dbhomedir"
                                                name="dbhomedir"
                                                onChange={(e, str) => this.handleChange(e, str)}
                                            />
                                        </GridItem>
                                    </Grid>
                                    <Grid
                                        title={_("The Time Of Day to perform the database compaction after the compact interval has been met.  Uses the format: 'HH:MM' and defaults to '23:59'. (nsslapd-db-compactdb-time)")}
                                        className="ds-margin-top"
                                    >
                                        <GridItem className="ds-label" span={4}>
                                            {_("Database Compaction Time")}
                                        </GridItem>
                                        <GridItem span={2}>
                                            <TimePicker
                                                time={this.state.compacttime}
                                                onChange={this.handleTimeChange}
                                                is24Hour
                                            />
                                        </GridItem>
                                    </Grid>
                                    <Grid
                                        title={_("The interval in seconds when the database is compacted (nsslapd-db-compactdb-interval). The default is 30 days at midnight. 0 is no compaction.")}
                                        className="ds-margin-top"
                                    >
                                        <GridItem className="ds-label" span={4}>
                                            {_("Database Compaction Interval")}
                                        </GridItem>
                                        <GridItem span={8}>
                                            <NumberInput
                                                value={this.state.compactinterval}
                                                min={0}
                                                max={this.maxValue}
                                                onMinus={() => { this.onMinusConfig("compactinterval") }}
                                                onChange={(e) => { this.onConfigChange(e, "compactinterval", 0, 0) }}
                                                onPlus={() => { this.onPlusConfig("compactinterval") }}
                                                inputName="input"
                                                inputAriaLabel="number input"
                                                minusBtnAriaLabel="minus"
                                                plusBtnAriaLabel="plus"
                                                widthChars={10}
                                                validated={'compactinterval' in this.state.error &&
                                                    this.state.error['compactinterval']
                                                     ? ValidatedOptions.error
                                                     : ValidatedOptions.default}
                                            />
                                        </GridItem>
                                    </Grid>
                                    <Grid
                                        title={_("Amount of time in seconds after which the Directory Server sends a checkpoint entry to the database transaction log (nsslapd-db-checkpoint-interval).")}
                                        className="ds-margin-top"
                                    >
                                        <GridItem className="ds-label" span={4}>
                                            {_("Database Checkpoint Interval")}
                                        </GridItem>
                                        <GridItem span={8}>
                                            <NumberInput
                                                value={this.state.chxpoint}
                                                min={10}
                                                max={300}
                                                onMinus={() => { this.onMinusConfig("chxpoint") }}
                                                onChange={(e) => { this.onConfigChange(e, "chxpoint", 10, 0) }}
                                                onPlus={() => { this.onPlusConfig("chxpoint") }}
                                                inputName="input"
                                                inputAriaLabel="number input"
                                                minusBtnAriaLabel="minus"
                                                plusBtnAriaLabel="plus"
                                                widthChars={10}
                                                validated={'chxpoint' in this.state.error &&
                                                    this.state.error['chxpoint']
                                                     ? ValidatedOptions.error
                                                     : ValidatedOptions.default}
                                            />
                                        </GridItem>
                                    </Grid>
                                </div>
                            </Tab>
                        </Tabs>
                    </div>

                    <Button
                        className="ds-margin-top-lg"
                        onClick={this.handleSaveDBConfig}
                        variant="primary"
                        isLoading={this.state.saving}
                        spinnerAriaValueText={this.state.saving ? _("Saving") : undefined}
                        {...extraPrimaryProps}
                        isDisabled={this.state.saveBtnDisabled || this.state.saving}
                    >
                        {saveBtnName}
                    </Button>
                </div>
            </div>
        );
    }
}

// Property types and defaults

GlobalDatabaseConfig.propTypes = {
    serverId: PropTypes.string,
    addNotification: PropTypes.func,
    data: PropTypes.object,
    reload: PropTypes.func,
    enableTree: PropTypes.func,
};

GlobalDatabaseConfig.defaultProps = {
    serverId: "",
    data: {},
};

export class GlobalDatabaseConfigMDB extends React.Component {
    ismounted = false;
    constructor(props) {
        super(props);
        this.state = {
            saving: false,
            saveBtnDisabled: true,
            availDbSizeBytes: 0,
            error: {},
            activeTabKey:  this.props.data.activeTab,
            db_cache_auto: this.props.data.db_cache_auto,
            import_cache_auto: this.props.data.import_cache_auto,
            looklimit: this.props.data.looklimit,
            idscanlimit: this.props.data.idscanlimit,
            pagelooklimit: this.props.data.pagelooklimit,
            pagescanlimit: this.props.data.pagescanlimit,
            rangelooklimit: this.props.data.rangelooklimit,
            dbhomedir: this.props.data.dbhomedir,
            mdbmaxsize: this.props.data.mdbmaxsize,
            mdbmaxreaders: this.props.data.mdbmaxreaders,
            mdbmaxdbs: this.props.data.mdbmaxdbs,
            ndncachemaxsize: this.props.data.ndncachemaxsize,
            // These variables store the original value (used for saving config)
            _looklimit: this.props.data.looklimit,
            _idscanlimit: this.props.data.idscanlimit,
            _pagelooklimit: this.props.data.pagelooklimit,
            _pagescanlimit: this.props.data.pagescanlimit,
            _rangelooklimit: this.props.data.rangelooklimit,
            _dbhomedir: this.props.data.dbhomedir,
            _mdbmaxsize: this.props.data.mdbmaxsize,
            _mdbmaxreaders: this.props.data.mdbmaxreaders,
            _mdbmaxdbs: this.props.data.mdbmaxdbs,
            _ndncachemaxsize: this.props.data.ndncachemaxsize,
        };

        this.validateSaveBtn = this.validateSaveBtn.bind(this);
        this.handleChange = this.handleChange.bind(this);
        this.handleSaveDBConfig = this.handleSaveDBConfig.bind(this);
        this.loadAvailableDiskSpace = this.loadAvailableDiskSpace.bind(this);

        this.maxValue = 2147483647;
        this.onMinusConfig = (id) => {
            if (id === "mdbmaxsize") {
                this.setState({
                    [id]: Number(this.state[id]) - (1024 * 1024),
                }, () => { this.validateSaveBtn() });
            } else {
                this.setState({
                    [id]: Number(this.state[id]) - 1,
                }, () => { this.validateSaveBtn() });
            }
        };

        this.onRangeConfigMinus = (id, special, lower) => {
            let value = isNaN(this.state[id]) ? 0 : Number(this.state[id]);
            if (value === lower) {
                value = special;
            } else {
                value -= 1;
            }
            this.setState({
                [id]: value
            }, () => { this.validateSaveBtn() });
        };

        this.onRangeConfigChange = (event, id) => {
            const value = isNaN(event.target.value) ? 0 : Number(event.target.value);
            this.setState({ [id]: value });
        };

        this.onRangeConfigChangeBlur = (id, special, lower, upper) => {
            let value = isNaN(this.state[id]) ? 0 : Number(this.state[id]);
            if (value === special) {
                // nothing to do
            } else if (value < lower) {
                value = lower;
            } else if (value > upper) {
                value = upper;
            }
            this.setState({
                [id]: value
            }, () => { this.validateSaveBtn() });
        };

        this.onConfigChange = (event, id, min, max) => {
            let maxValue = this.maxValue;
            if (max !== 0) {
                maxValue = max;
            }
            const newValue = isNaN(event.target.value) ? 0 : Number(event.target.value);
            if (id === "mdbmaxsize") {
                const newValueBytes = newValue * (1024 * 1024);
                this.setState({
                    [id]: (newValueBytes > max ? max : newValueBytes < min ? min : newValueBytes)
                }, () => { this.validateSaveBtn() });
            } else {
                let error = this.state.error;
                let badValue = false;
                const newValue = isNaN(event.target.value) ? 0 : Number(event.target.value);
                if (newValue > maxValue || newValue < min) {
                    badValue = true;

                }
                error[id] = badValue;
                this.setState({
                    [id]: newValue,
                    error,
                }, () => { this.validateSaveBtn() });
            }
        };

        this.onPlusConfig = (id) => {
            if (id === "mdbmaxsize") {
                this.setState({
                    [id]: Number(this.state[id]) + (1024 * 1024),
                }, () => { this.validateSaveBtn() });
            } else {
                this.setState({
                    [id]: Number(this.state[id]) + 1,
                }, () => { this.validateSaveBtn() });
            }
        };

        this.onRangeConfigPlus = (id, special, lower) => {
            let value = isNaN(this.state[id]) ? 0 : Number(this.state[id]);
            if (value === special) {
                value = lower;
            } else {
                value += 1;
            }
            this.setState({
                [id]: value
            }, () => { this.validateSaveBtn() });
        };

        // Toggle currently active tab
        this.handleNavSelect = (event, tabIndex) => {
            this.setState({
                activeTabKey: tabIndex
            });
        };
    }

    componentDidMount() {
        this.ismounted = true;
        this.props.enableTree();
        this.loadAvailableDiskSpace();
    }

    componentWillUnmount() {
        this.ismounted = false;
    }

    validateSaveBtn() {
        let saveBtnDisabled = true;
        const check_attrs = [
            "looklimit", "idscanlimit", "pagelooklimit",
            "pagescanlimit", "rangelooklimit", "ndncachemaxsize",
            "mdbmaxsize", "mdbmaxreaders", "mdbmaxdbs",
        ];

        // Check if a setting was changed, if so enable the save button
        for (const config_attr of check_attrs) {
            if (this.state[config_attr] !== this.state['_' + config_attr]) {
                saveBtnDisabled = false;
                break;
            }
        }

        // Check if have any errors on our attributes
        for (const config_attr of check_attrs) {
            if (config_attr in this.state.error && this.state.error[config_attr]) {
                saveBtnDisabled = true;
                break;
            }
        }

        this.setState({
            saveBtnDisabled
        });
    }

    handleChange(e, str) {
        // Generic
        const value = e.target.type === 'checkbox' ? e.target.checked : e.target.value;
        const attr = e.target.id;

        this.setState({
            [attr]: value,
        }, () => { this.validateSaveBtn() });
    }

    save_ndn_cache(requireRestart) {
        const msg = "Successfully updated database configuration";
        if (this.state._ndncachemaxsize !== this.state.ndncachemaxsize) {
            const cmd = [
                'dsconf', '-j', 'ldapi://%2fvar%2frun%2fslapd-' + this.props.serverId + '.socket',
                'config', 'replace', 'nsslapd-ndn-cache-max-size=' + this.state.ndncachemaxsize
            ];

            log_cmd("save_ndn_cache", "Applying config change", cmd);
            cockpit
                    .spawn(cmd, { superuser: true, err: "message" })
                    .done(content => {
                        this.props.reload(this.state.activeTabKey);
                        this.setState({
                            saving: false
                        });
                        if (requireRestart) {
                            this.props.addNotification(
                                "warning",
                                cockpit.format(_("$0. You must restart the Directory Server for these changes to take effect."), msg)
                            );
                        } else {
                            this.props.addNotification(
                                "success",
                                msg
                            );
                        }
                    })
                    .fail(err => {
                        const errMsg = JSON.parse(err);
                        this.props.reload(this.state.activeTabKey);
                        this.setState({
                            saving: false
                        });
                        this.props.addNotification(
                            "error",
                            cockpit.format(_("Error updating configuration - $0"), errMsg.desc)
                        );
                    });
        } else {
            this.props.reload(this.state.activeTabKey);
            this.setState({
                saving: false
            });
            if (requireRestart) {
                this.props.addNotification(
                    "warning",
                    cockpit.format(_("$0. You must restart the Directory Server for these changes to take effect."), msg)
                );
            } else {
                this.props.addNotification(
                    "success",
                    msg
                );
            }
        }
    }

    handleSaveDBConfig() {
        // Build up the command list
        const cmd = [
            'dsconf', '-j', 'ldapi://%2fvar%2frun%2fslapd-' + this.props.serverId + '.socket',
            'backend', 'config', 'set'
        ];
        let requireRestart = false;

        if (this.state._looklimit !== this.state.looklimit) {
            cmd.push("--lookthroughlimit=" + this.state.looklimit);
        }
        if (this.state._idscanlimit !== this.state.idscanlimit) {
            cmd.push("--idlistscanlimit=" + this.state.idscanlimit);
        }
        if (this.state._pagelooklimit !== this.state.pagelooklimit) {
            cmd.push("--pagedlookthroughlimit=" + this.state.pagelooklimit);
        }
        if (this.state._pagescanlimit !== this.state.pagescanlimit) {
            cmd.push("--pagedidlistscanlimit=" + this.state.pagescanlimit);
        }
        if (this.state._rangelooklimit !== this.state.rangelooklimit) {
            cmd.push("--rangelookthroughlimit=" + this.state.rangelooklimit);
        }
        if (this.state._mdbmaxsize !== this.state.mdbmaxsize) {
            cmd.push("--mdb-max-size=" + this.state.mdbmaxsize);
            requireRestart = true;
        }
        if (this.state._mdbmaxreaders !== this.state.mdbmaxreaders) {
            cmd.push("--mdb-max-readers=" + this.state.mdbmaxreaders);
            requireRestart = true;
        }
        if (this.state._mdbmaxdbs !== this.state.mdbmaxdbs) {
            cmd.push("--mdb-max-dbs=" + this.state.mdbmaxdbs);
            requireRestart = true;
        }
        if (cmd.length > 6) {
            this.setState({
                saving: true
            });
            log_cmd("handleSaveDBConfig", "Applying config change", cmd);
            cockpit
                    .spawn(cmd, { superuser: true, err: "message" })
                    .done(content => {
                        // Continue with the next mod
                        this.save_ndn_cache(requireRestart);
                    })
                    .fail(err => {
                        const errMsg = JSON.parse(err);
                        this.props.reload(this.state.activeTabKey);
                        this.setState({
                            saving: false
                        });
                        this.props.addNotification(
                            "error",
                            cockpit.format(_("Error updating configuration - $0"), errMsg.desc)
                        );
                    });
        } else {
            this.setState({
                saving: true
            }, () => { this.save_ndn_cache(requireRestart) });
        }
    }

    loadAvailableDiskSpace() {
        let available = 0;
        const cmd = "df -B1 " + this.state.dbhomedir + " | awk '{print $4}'";
        // log_cmd("loadAvailableDiskSpace", "Load available disk space", cmd);
        cockpit
                .script(cmd, [], { superuser: true, err: "message" })
                .done(output => {
                    available = output.split(/\s+/)[1];
                    if (this.ismounted) {
                        this.setState({
                            availDbSizeBytes: available,
                        });
                    }
                })
                .fail(() => {
                    this.setState({
                        availDbSizeBytes: available,
                    });
                });
    }

    render() {
        let spinner = "";
        if (this.state.loading) {
            spinner = (
                <div className="ds-loading-spinner ds-margin-top-xlg ds-center">
                    <TextContent>
                        <Text component={TextVariants.h3}>
                            Loading global database configuration ...
                        </Text>
                    </TextContent>
                    <Spinner className="ds-margin-top" loading size="md" />
                </div>
            );
        }

        let saveBtnName = _("Save Config");
        const extraPrimaryProps = {};
        if (this.props.refreshing) {
            saveBtnName = _("Saving config ...");
            extraPrimaryProps.spinnerAriaValueText = _("Saving");
        }

        return (
            <div className={this.state.saving ? "ds-disabled ds-margin-bottom-md" : "ds-margin-bottom-md"} id="db-global-page">
                {spinner}
                <div className={this.state.loading ? 'ds-fadeout' : 'ds-fadein'}>
                    <TextContent>
                        <Text className="ds-config-header" component={TextVariants.h2}>
                            {_("Global Database Configuration")}
                            <Button
                                variant="plain"
                                aria-label={_("Refresh config settings")}
                                onClick={() => {
                                    this.props.reload(this.state.activeTabKey);
                                }}
                            >
                                <SyncAltIcon />
                            </Button>
                        </Text>
                    </TextContent>

                    <div className="ds-margin-top-lg">
                        <Tabs isFilled activeKey={this.state.activeTabKey} onSelect={this.handleNavSelect}>
                            <Tab eventKey={0} title={<TabTitleText>{_("Database Size")}</TabTitleText>}>
                                <div className="ds-left-indent-md">
                                    <Grid
                                        title={_("Database maximum size in megabytes. The practical maximum size of an LMDB database is limited by the system's addressable memory (nsslapd-mdb-max-size).")}
                                        className="ds-margin-top-xlg"
                                    >
                                        <GridItem className="ds-label" span={4}>
                                            {_("Database Maximum Size")}
                                        </GridItem>
                                        <GridItem span={8}>
                                            <NumberInput
                                                value={Math.floor(this.state.mdbmaxsize / (1024 * 1024))}
                                                min={104857600 / (1024 * 1024)}
                                                max={Math.floor(this.state.availDbSizeBytes / (1024 * 1024))}
                                                onMinus={() => { this.onMinusConfig("mdbmaxsize") }}
                                                onChange={(e) => { this.onConfigChange(e, "mdbmaxsize", 104857600, this.state.availDbSizeBytes) }}
                                                onPlus={() => { this.onPlusConfig("mdbmaxsize") }}
                                                inputName="input"
                                                inputAriaLabel="number input"
                                                minusBtnAriaLabel="minus"
                                                plusBtnAriaLabel="plus"
                                                unit="MB"
                                                widthChars={10}
                                                validated={'mdbmaxsize' in this.state.error &&
                                                    this.state.error['mdbmaxsize']
                                                     ? ValidatedOptions.error
                                                     : ValidatedOptions.default}
                                            />
                                        </GridItem>
                                    </Grid>
                                </div>
                            </Tab>
                            <Tab eventKey={1} title={<TabTitleText>{_("Limits")}</TabTitleText>}>
                                <div className="ds-left-indent-md">
                                    <Grid
                                        title={_("The maximum number of entries that the Directory Server will check when examining candidate entries in response to a search request (nsslapd-lookthrough-limit).")}
                                        className="ds-margin-top-xlg"
                                    >
                                        <GridItem className="ds-label" span={4}>
                                            {_("Database Look Through Limit")}
                                        </GridItem>
                                        <GridItem span={8}>
                                            <NumberInput
                                                value={this.state.looklimit}
                                                min={-1}
                                                max={this.maxValue}
                                                onMinus={() => { this.onMinusConfig("looklimit") }}
                                                onChange={(e) => { this.onConfigChange(e, "looklimit", -1, 0) }}
                                                onPlus={() => { this.onPlusConfig("looklimit") }}
                                                inputName="input"
                                                inputAriaLabel="number input"
                                                minusBtnAriaLabel="minus"
                                                plusBtnAriaLabel="plus"
                                                widthChars={10}
                                                validated={'looklimit' in this.state.error &&
                                                    this.state.error['looklimit']
                                                     ? ValidatedOptions.error
                                                     : ValidatedOptions.default}
                                            />
                                        </GridItem>
                                    </Grid>
                                    <Grid
                                        title={_("The number of entry IDs that are searched during a search operation (nsslapd-idlistscanlimit).")}
                                        className="ds-margin-top-xlg"
                                    >
                                        <GridItem className="ds-label" span={4}>
                                            {_("ID List Scan Limit")}
                                        </GridItem>
                                        <GridItem span={8}>
                                            <NumberInput
                                                value={this.state.idscanlimit}
                                                min={100}
                                                max={this.maxValue}
                                                onMinus={() => { this.onMinusConfig("idscanlimit") }}
                                                onChange={(e) => { this.onConfigChange(e, "idscanlimit", 100, 0) }}
                                                onPlus={() => { this.onPlusConfig("idscanlimit") }}
                                                inputName="input"
                                                inputAriaLabel="number input"
                                                minusBtnAriaLabel="minus"
                                                plusBtnAriaLabel="plus"
                                                widthChars={10}
                                                validated={'idscanlimit' in this.state.error &&
                                                    this.state.error['idscanlimit']
                                                     ? ValidatedOptions.error
                                                     : ValidatedOptions.default}
                                            />
                                        </GridItem>
                                    </Grid>
                                    <Grid
                                        title={_("The maximum number of entries that the Directory Server will check when examining candidate entries for a search which uses the simple paged results control (nsslapd-pagedlookthroughlimit).")}
                                        className="ds-margin-top-xlg"
                                    >
                                        <GridItem className="ds-label" span={4}>
                                            {_("Paged Search Look Through Limit")}
                                        </GridItem>
                                        <GridItem span={8}>
                                            <NumberInput
                                                value={this.state.pagelooklimit}
                                                min={-1}
                                                max={this.maxValue}
                                                onMinus={() => { this.onMinusConfig("pagelooklimit") }}
                                                onChange={(e) => { this.onConfigChange(e, "pagelooklimit", -1, 0) }}
                                                onPlus={() => { this.onPlusConfig("pagelooklimit") }}
                                                inputName="input"
                                                inputAriaLabel="number input"
                                                minusBtnAriaLabel="minus"
                                                plusBtnAriaLabel="plus"
                                                widthChars={10}
                                                validated={'pagelooklimit' in this.state.error &&
                                                    this.state.error['pagelooklimit']
                                                     ? ValidatedOptions.error
                                                     : ValidatedOptions.default}
                                            />
                                        </GridItem>
                                    </Grid>
                                    <Grid
                                        title={_("The number of entry IDs that are searched, specifically, for a search operation using the simple paged results control (nsslapd-pagedidlistscanlimit).")}
                                        className="ds-margin-top-xlg"
                                    >
                                        <GridItem className="ds-label" span={4}>
                                            {_("Paged Search ID List Scan Limit")}
                                        </GridItem>
                                        <GridItem span={8}>
                                            <NumberInput
                                                value={this.state.pagescanlimit}
                                                min={-1}
                                                max={this.maxValue}
                                                onMinus={() => { this.onMinusConfig("pagescanlimit") }}
                                                onChange={(e) => { this.onConfigChange(e, "pagescanlimit", -1, 0) }}
                                                onPlus={() => { this.onPlusConfig("pagescanlimit") }}
                                                inputName="input"
                                                inputAriaLabel="number input"
                                                minusBtnAriaLabel="minus"
                                                plusBtnAriaLabel="plus"
                                                widthChars={10}
                                                validated={'pagescanlimit' in this.state.error &&
                                                    this.state.error['pagescanlimit']
                                                     ? ValidatedOptions.error
                                                     : ValidatedOptions.default}
                                            />
                                        </GridItem>
                                    </Grid>
                                    <Grid
                                        title={_("The maximum number of entries that the Directory Server will check when examining candidate entries in response to a range search request (nsslapd-rangelookthroughlimit).")}
                                        className="ds-margin-top-xlg"
                                    >
                                        <GridItem className="ds-label" span={4}>
                                            {_("Range Search Look Through Limit")}
                                        </GridItem>
                                        <GridItem span={8}>
                                            <NumberInput
                                                value={this.state.rangelooklimit}
                                                min={-1}
                                                max={this.maxValue}
                                                onMinus={() => { this.onMinusConfig("rangelooklimit") }}
                                                onChange={(e) => { this.onConfigChange(e, "rangelooklimit", -1, 0) }}
                                                onPlus={() => { this.onPlusConfig("rangelooklimit") }}
                                                inputName="input"
                                                inputAriaLabel="number input"
                                                minusBtnAriaLabel="minus"
                                                plusBtnAriaLabel="plus"
                                                widthChars={10}
                                                validated={'rangelooklimit' in this.state.error &&
                                                    this.state.error['rangelooklimit']
                                                     ? ValidatedOptions.error
                                                     : ValidatedOptions.default}
                                            />
                                        </GridItem>
                                    </Grid>
                                </div>
                            </Tab>

                            <Tab eventKey={4} title={<TabTitleText>{_("NDN Cache")}</TabTitleText>}>
                                <div className="ds-left-indent-md">
                                    <Grid
                                        title={_("Warning: Normalized DN Cache is disabled")}
                                        className="ds-margin-top-xlg"
                                    >
                                        {this.props.data.ndn_cache_enabled === false && (
                                            <GridItem span={8}>
                                                <Alert
                                                    variant="warning"
                                                    isInline
                                                    title={_("Normalized DN Cache is disabled")}
                                                    className="ds-margin-bottom"
                                                >
                                                    {_("The Normalized DN Cache is currently disabled. To enable it, go to Server Settings → Tuning & Limits and enable 'Normalized DN Cache', then restart the server for the changes to take effect.")}
                                                </Alert>
                                            </GridItem>
                                        )}
                                    </Grid>
                                    <Grid
                                        title={_("Set the maximum size in bytes for the Normalized DN Cache (nsslapd-ndn-cache-max-size).")}
                                        className="ds-margin-top-xlg"
                                    >
                                        <GridItem className="ds-label" span={4}>
                                            {_("Normalized DN Cache Max Size") }
                                        </GridItem>
                                        <GridItem span={8}>
                                            <NumberInput
                                                value={this.state.ndncachemaxsize}
                                                min={1000000}
                                                max={this.maxValue}
                                                onMinus={() => { this.onMinusConfig("ndncachemaxsize") }}
                                                onChange={(e) => { this.onConfigChange(e, "ndncachemaxsize", 1000000, 0) }}
                                                onPlus={() => { this.onPlusConfig("ndncachemaxsize") }}
                                                inputName="input"
                                                inputAriaLabel="number input"
                                                minusBtnAriaLabel="minus"
                                                plusBtnAriaLabel="plus"
                                                widthChars={10}
                                                validated={'ndncachemaxsize' in this.state.error &&
                                                           this.state.error['ndncachemaxsize']
                                                            ? ValidatedOptions.error
                                                            : ValidatedOptions.default}
                                            />
                                        </GridItem>
                                    </Grid>
                                </div>
                            </Tab>

                            <Tab eventKey={5} title={<TabTitleText>{_("Advanced Settings")}</TabTitleText>}>
                                <div className="ds-left-indent-md">
                                    <Grid
                                        title={_("Location for database memory mapped files, this element is read only.")}
                                            className="ds-margin-top"
                                    >
                                        <GridItem className="ds-label" span={4}>
                                            {_("Database Home Directory")}
                                        </GridItem>
                                        <GridItem span={8}>
                                            <TextInput
                                                value={this.state.dbhomedir}
                                                type="text"
                                                readOnlyVariant='plain'
                                                id="dbhomedir"
                                                aria-describedby="dbhomedir"
                                                name="dbhomedir read only"
                                            />
                                        </GridItem>
                                    </Grid>
                                    <Grid
                                        title={_("The maximum number of read transactions that can be opened simultaneously. A value of 0 means this value is computed by the server (nsslapd-mdb-max-readers).")}
                                        className="ds-margin-top-xlg"
                                    >
                                        <GridItem className="ds-label" span={4}>
                                            {_("Database Max Readers")}
                                        </GridItem>
                                        <GridItem span={8}>
                                            <NumberInput
                                                value={this.state.mdbmaxreaders}
                                                min={0}
                                                max={200}
                                                onMinus={() => { this.onRangeConfigMinus("mdbmaxreaders", 0, 26) }}
                                                onChange={(e) => { this.onRangeConfigChange(e, "mdbmaxreaders") }}
                                                onBlur={() => { this.onRangeConfigChangeBlur("mdbmaxreaders", 0, 26, 200) }}
                                                onPlus={() => { this.onRangeConfigPlus("mdbmaxreaders", 0, 26) }}
                                                inputName="input"
                                                inputAriaLabel="number input"
                                                minusBtnAriaLabel="minus"
                                                plusBtnAriaLabel="plus"
                                                widthChars={10}
                                                validated={'mdbmaxreaders' in this.state.error &&
                                                    this.state.error['mdbmaxreaders']
                                                     ? ValidatedOptions.error
                                                     : ValidatedOptions.default}
                                            />
                                        </GridItem>
                                    </Grid>
                                    <Grid
                                        title={_("The maximum number of named database instances that can be included within the memory mapped database file. A value of 0 means this value is computed by the server (nsslapd-mdb-max-dbs).")}
                                        className="ds-margin-top-xlg"
                                    >
                                        <GridItem className="ds-label" span={4}>
                                            {_("Database Max DBs")}
                                        </GridItem>
                                        <GridItem span={8}>
                                            <NumberInput
                                                value={this.state.mdbmaxdbs}
                                                min={0}
                                                max={5000}
                                                onMinus={() => { this.onRangeConfigMinus("mdbmaxdbs", 0, 131) }}
                                                onChange={(e) => { this.onRangeConfigChange(e, "mdbmaxdbs") }}
                                                onBlur={() => { this.onRangeConfigChangeBlur("mdbmaxdbs", 0, 131, 5000) }}
                                                onPlus={() => { this.onRangeConfigPlus("mdbmaxdbs", 0, 131) }}
                                                inputName="input"
                                                inputAriaLabel="number input"
                                                minusBtnAriaLabel="minus"
                                                plusBtnAriaLabel="plus"
                                                widthChars={10}
                                                validated={'mdbmaxdbs' in this.state.error &&
                                                    this.state.error['mdbmaxdbs']
                                                     ? ValidatedOptions.error
                                                     : ValidatedOptions.default}
                                            />
                                        </GridItem>
                                    </Grid>
                                </div>
                            </Tab>
                        </Tabs>
                    </div>
                    <Button
                        className="ds-margin-top-lg"
                        onClick={this.handleSaveDBConfig}
                        variant="primary"
                        isLoading={this.state.saving}
                        spinnerAriaValueText={this.state.saving ? _("Saving") : undefined}
                        {...extraPrimaryProps}
                        isDisabled={this.state.saveBtnDisabled || this.state.saving}
                    >
                        {saveBtnName}
                    </Button>
                </div>
            </div>
        );
    }
}

// Property types and defaults

GlobalDatabaseConfigMDB.propTypes = {
    serverId: PropTypes.string,
    addNotification: PropTypes.func,
    data: PropTypes.object,
    reload: PropTypes.func,
    enableTree: PropTypes.func,
};

GlobalDatabaseConfigMDB.defaultProps = {
    serverId: "",
    data: {},
};
