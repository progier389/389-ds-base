import cockpit from "cockpit";
import React from "react";
import { DoubleConfirmModal } from "../notifications.jsx";
import { log_cmd, listsEqual } from "../tools.jsx";
import {
	Button,
	Checkbox,
	Form,
	Grid,
	GridItem,
	Spinner,
	TextInput,
	Text,
	TextContent,
	TextVariants
} from '@patternfly/react-core';
import {
	Select,
	SelectVariant,
	SelectOption
} from '@patternfly/react-core/deprecated';
import { SASLTable } from "./serverTables.jsx";
import { SASLMappingModal } from "./serverModals.jsx";
import { SyncAltIcon } from "@patternfly/react-icons";

const _ = cockpit.gettext;

export class ServerSASL extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            configLoading: false,
            tableLoading: false,
            loaded: false,
            activeKey: 1,
            errObj: {},
            saveDisabled: true,
            supportedMechs: [],
            mappingKey: 0,

            // Main settings
            allowedMechs: [],
            mappingFallback: false,
            maxBufSize: "",
            // Mapping modal
            showMapping: false,
            saveMappingDisabled: true,
            testRegexDisabled: true,
            testBtnDisabled: true,
            saslMapName: "",
            saslMapRegex: "",
            saslTestText: "",
            saslBase: "",
            saslFilter: "",
            saslPriority: "100",
            saslModalType: _("Create"),
            saslErrObj: {},
            showConfirmDelete: false,
            modalChecked: false,
            isAllowedMechOpen: false,
        };
        // Allowed SASL Mechanisms
        this.handleOnAllowedMechToggle = (_event, isAllowedMechOpen) => {
            this.setState({
                isAllowedMechOpen,
            });
        };
        this.handleOnSelect = (event, selection) => {
            const { allowedMechs } = this.state;
            if (allowedMechs.includes(selection)) {
                this.setState(
                    prevState => ({
                        allowedMechs: prevState.allowedMechs.filter(item => item !== selection),
                        isAllowedMechOpen: false
                    }), () => { this.validateSaveBtn() }
                );
            } else {
                this.setState(
                    prevState => ({
                        allowedMechs: [...prevState.allowedMechs, selection],
                        isAllowedMechOpen: false,
                    }), () => { this.validateSaveBtn() }
                );
            }
        };
        this.handleOnAllowedMechClear = () => {
            this.setState({
                allowedMechs: [],
                isAllowedMechOpen: false
            });
        };

        this.validateRegex = this.validateRegex.bind(this);
        this.validateModal = this.validateModal.bind(this);
        this.validateSaveBtn = this.validateSaveBtn.bind(this);
        this.handleChange = this.handleChange.bind(this);
        this.onModalChange = this.onModalChange.bind(this);
        this.onTestRegex = this.onTestRegex.bind(this);
        this.handleLoadConfig = this.handleLoadConfig.bind(this);
        this.loadMechs = this.loadMechs.bind(this);
        this.loadSASLMappings = this.loadSASLMappings.bind(this);
        this.handleSaveConfig = this.handleSaveConfig.bind(this);
        this.handleShowCreateMapping = this.handleShowCreateMapping.bind(this);
        this.showEditMapping = this.showEditMapping.bind(this);
        this.closeMapping = this.closeMapping.bind(this);
        this.showConfirmDelete = this.showConfirmDelete.bind(this);
        this.closeConfirmDelete = this.closeConfirmDelete.bind(this);
        this.createMapping = this.createMapping.bind(this);
        this.editMapping = this.editMapping.bind(this);
        this.deleteMapping = this.deleteMapping.bind(this);
    }

    componentDidMount() {
        // Loading config
        if (!this.state.loaded) {
            this.handleLoadConfig();
        } else {
            this.props.enableTree();
        }
    }

    normalizeRegex(regex_str) {
        return regex_str.replace(/\\\(/g, '(').replace(/\\\)/g, ')');
    }

    validateRegex(regex) {
        // Just check that the regex itself is valid
        const errObj = this.state.saslErrObj;
        let saveMappingDisabled = this.state.saveMappingDisabled;
        if (this.state.saslMapRegex === "") {
            errObj.saslMapRegex = true;
        } else {
            try {
                RegExp(this.state.saslMapRegex);
                const cleaned_regex = this.normalizeRegex(this.state.saslMapRegex);
                // Test the normalized version
                RegExp(cleaned_regex);
                errObj.saslMapRegex = false;
            } catch (e) {
                // Bad regex
                errObj.saslMapRegex = true;
                saveMappingDisabled = true;
            }
        }
        this.setState({
            saslErrObj: errObj,
            saveMappingDisabled

        });
        return !errObj.saslMapRegex;
    }

    onTestRegex() {
        const test_string = this.state.saslTestText;
        if (this.validateRegex()) {
            const cleaned_regex = this.normalizeRegex(this.state.saslMapRegex);
            const sasl_regex = RegExp(cleaned_regex);
            if (sasl_regex.test(test_string)) {
                this.props.addNotification(
                    "success",
                    _("The test string matches the Regular Expression")
                );
            } else {
                this.props.addNotification(
                    "warning",
                    _("The test string does not match the Regular Expression")
                );
            }
        } else {
            this.props.addNotification(
                "error",
                _("Invalid regular expression")
            );
        }
    }

    validateSaveBtn() {
        const attrs = ['mappingFallback', 'maxBufSize'];
        let disableSaveBtn = true;

        for (const attr of attrs) {
            if (this.state[attr] !== this.state['_' + attr]) {
                disableSaveBtn = false;
                break;
            }
        }

        const orig_mechs = [...this.state._allowedMechs];
        const new_mechs = [...this.state.allowedMechs];
        if (!listsEqual(orig_mechs, new_mechs)) {
            disableSaveBtn = false;
        }

        this.setState({
            saveDisabled: disableSaveBtn,
        });
    }

    handleChange(e) {
        let attr = "";
        let value = "";

        value = e.target.type === 'checkbox' ? e.target.checked : e.target.value;
        attr = e.target.id;

        this.setState({
            [attr]: value,
            isAllowedMechOpen: false
        }, () => { this.validateSaveBtn() });
    }

    validateModal() {
        let disableSaveBtn = true;
        let disableRegexTestBtn = true;
        const errObj = this.state.saslErrObj;
        let error = false;

        const attrs = ['saslMapName', 'saslMapRegex', 'saslBase', 'saslPriority', 'saslFilter'];
        for (const attr of attrs) {
            if (this.state[attr] === "" || (attr === 'saslPriority' && this.state[attr] === "0")) {
                errObj[attr] = true;
                error = true;
            } else {
                // attr value is good
                errObj[attr] = false;
            }
        }

        if (!error) {
            // Check for changes in values
            for (const attr of attrs) {
                if (this.state[attr] !== this.state['_' + attr]) {
                    disableSaveBtn = false;
                    break;
                }
            }
        }

        // Handle Test Text field and buttons
        if (this.state.saslMapRegex !== "" && this.state.saslTestText !== "") {
            disableRegexTestBtn = false;
        }

        this.setState({
            saveMappingDisabled: disableSaveBtn,
            testBtnDisabled: disableRegexTestBtn,
            saslErrObj: errObj,
        }, () => { this.validateRegex() });
    }

    onModalChange(e) {
        const value = e.target.type === 'checkbox' ? e.target.checked : e.target.value;
        const attr = e.target.id;

        this.setState({
            [attr]: value,
        }, () => { this.validateModal() });
    }

    handleLoadConfig() {
        const cmd = [
            "dsconf", "-j", "ldapi://%2fvar%2frun%2fslapd-" + this.props.serverId + ".socket",
            "config", 'get'
        ];
        log_cmd("handleLoadConfig", "Get SASL settings", cmd);
        cockpit
                .spawn(cmd, { superuser: true, err: "message" })
                .done(content => {
                    const config = JSON.parse(content);
                    const attrs = config.attrs;
                    let allowedMechsVal = attrs['nsslapd-allowed-sasl-mechanisms'][0];
                    let allowedMechs = [];
                    let fallback = false;

                    if (attrs['nsslapd-sasl-mapping-fallback'][0] === "on") {
                        fallback = true;
                    }
                    if (allowedMechsVal !== "") {
                        // Could be space or comma separated
                        if (allowedMechsVal.indexOf(',') > -1) {
                            allowedMechsVal = allowedMechsVal.trim();
                            allowedMechs = allowedMechsVal.split(',');
                        } else {
                            allowedMechs = allowedMechsVal.split(' ');
                        }
                    }

                    this.setState({
                        maxBufSize: attrs['nsslapd-sasl-max-buffer-size'][0],
                        allowedMechs,
                        mappingFallback: fallback,
                        saveDisabled: true,
                        // Store original values
                        _maxBufSize: attrs['nsslapd-sasl-max-buffer-size'][0],
                        _allowedMechs: allowedMechs,
                        _mappingFallback: fallback,
                    }, this.loadMechs());
                });
    }

    loadMechs() {
        const cmd = [
            "dsconf", "-j", "ldapi://%2fvar%2frun%2fslapd-" + this.props.serverId + ".socket", "sasl", 'get-available-mechs'
        ];
        log_cmd("loadMechs", "Get supported SASL mechanisms", cmd);
        cockpit
                .spawn(cmd, { superuser: true, err: "message" })
                .done(content => {
                    const config = JSON.parse(content);
                    this.setState({
                        supportedMechs: config.items
                    }, this.loadSASLMappings());
                });
    }

    loadSASLMappings() {
        const cmd = ["dsconf", '-j', "ldapi://%2fvar%2frun%2fslapd-" + this.props.serverId + ".socket", 'sasl', 'list', '--details'];
        log_cmd('get_and_set_sasl', 'Get SASL mappings', cmd);
        cockpit
                .spawn(cmd, { superuser: true, err: "message" })
                .done(content => {
                    const saslMapObj = JSON.parse(content);
                    const mappings = [];
                    for (const mapping of saslMapObj.items) {
                        if (!('nssaslmappriority' in mapping.attrs)) {
                            mapping.attrs.nssaslmappriority = ['100'];
                        }
                        mappings.push(mapping.attrs);
                    }
                    const key = this.state.mappingKey + 1;
                    this.setState({
                        mappings,
                        mappingKey: key,
                        loaded: true,
                        tableLoading: false,
                        configLoading: false,
                        showMappingModal: false,
                        showConfirmDelete: false,
                    }, this.props.enableTree);
                });
    }

    handleShowCreateMapping() {
        this.setState({
            showMappingModal: true,
            saveMappingDisabled: true,
            testRegexDisabled: true,
            saslModalType: _("Create"),
            saslMapName: "",
            saslMapRegex: "",
            saslTestText: "",
            saslBase: "",
            saslFilter: "",
            saslPriority: "100",
            saslErrObj: {},
        });
    }

    closeMapping() {
        this.setState({
            showMappingModal: false,
        });
    }

    showEditMapping(name, regex, base, filter, priority) {
        this.setState({
            showMappingModal: true,
            saveMappingDisabled: true,
            testRegexDisabled: true,
            saslModalType: _("Edit"),
            saslMapName: name,
            saslMapRegex: regex,
            saslTestText: "",
            saslBase: base,
            saslFilter: filter,
            saslPriority: priority,
            // Note original values
            _saslMapName: name,
            _saslMapRegex: regex,
            _saslTestText: "",
            _saslBase: base,
            _saslFilter: filter,
            _saslPriority: priority,
            saslErrObj: {},
        });
    }

    showConfirmDelete(name) {
        this.setState({
            saslMapName: name,
            modalChecked: false,
            showConfirmDelete: true,
        });
    }

    closeConfirmDelete() {
        this.setState({
            modalChecked: false,
            showConfirmDelete: false,
        });
    }

    createMapping() {
        this.setState({
            tableLoading: true,
        });
        const cmd = [
            'dsconf', '-j', "ldapi://%2fvar%2frun%2fslapd-" + this.props.serverId + ".socket",
            'sasl', 'create',
            '--cn=' + this.state.saslMapName,
            '--nsSaslMapFilterTemplate=' + this.state.saslFilter,
            '--nsSaslMapRegexString=' + this.state.saslMapRegex,
            '--nsSaslMapBaseDNTemplate=' + this.state.saslBase,
            '--nsSaslMapPriority=' + this.state.saslPriority
        ];

        log_cmd("createMapping", "Create sasl mapping", cmd);
        cockpit
                .spawn(cmd, { superuser: true, err: "message" })
                .done(content => {
                    this.handleLoadConfig();
                    this.props.addNotification(
                        "success",
                        _("Successfully create new SASL Mapping")
                    );
                })
                .fail(err => {
                    const errMsg = JSON.parse(err);
                    this.handleLoadConfig();
                    this.props.addNotification(
                        "error",
                        cockpit.format(_("Error creating new SASL Mapping - $0"), errMsg.desc)
                    );
                });
    }

    editMapping(name) {
        // Start spinning
        const new_mappings = this.state.mappings;
        for (const saslMap of new_mappings) {
            if (saslMap.cn[0] === name) {
                saslMap.nssaslmapregexstring = [<Spinner className="ds-lower-field" key={new_mappings[0].nssaslmapregexstring[0]} loading size="sm" />];
                saslMap.nssaslmapbasedntemplate = [<Spinner className="ds-lower-field" key={new_mappings[0].nssaslmapbasedntemplate[0]} loading size="sm" />];
                saslMap.nssaslmapfiltertemplate = [<Spinner className="ds-lower-field" key={new_mappings[0].nssaslmapfiltertemplate[0]} loading size="sm" />];
                saslMap.nssaslmappriority = [<Spinner className="ds-lower-field" key={new_mappings[0].nssaslmappriority[0]} loading size="sm" />];
            }
        }

        this.setState({
            mappings: new_mappings,
            tableLoading: true
        });

        // Delete and create
        const delete_cmd = [
            'dsconf', '-j', "ldapi://%2fvar%2frun%2fslapd-" + this.props.serverId + ".socket",
            'sasl', 'delete', this.state._saslMapName
        ];
        const create_cmd = [
            'dsconf', '-j', "ldapi://%2fvar%2frun%2fslapd-" + this.props.serverId + ".socket",
            'sasl', 'create',
            '--cn=' + this.state.saslMapName,
            '--nsSaslMapFilterTemplate=' + this.state.saslFilter,
            '--nsSaslMapRegexString=' + this.state.saslMapRegex,
            '--nsSaslMapBaseDNTemplate=' + this.state.saslBase,
            '--nsSaslMapPriority=' + this.state.saslPriority
        ];

        log_cmd("editMapping", "deleting sasl mapping", delete_cmd);
        cockpit
                .spawn(delete_cmd, { superuser: true, err: "message" })
                .done(content => {
                    log_cmd("editMapping", "Create new sasl mapping", create_cmd);
                    cockpit
                            .spawn(create_cmd, { superuser: true, err: "message" })
                            .done(content => {
                                this.handleLoadConfig();
                                this.props.addNotification(
                                    "success",
                                    _("Successfully updated SASL Mapping")
                                );
                            })
                            .fail(err => {
                                const errMsg = JSON.parse(err);
                                this.closeMapping();
                                this.handleLoadConfig();
                                this.props.addNotification(
                                    "error",
                                    cockpit.format(_("Error updating SASL Mapping - $0"), errMsg.desc)
                                );
                            });
                })
                .fail(err => {
                    const errMsg = JSON.parse(err);
                    this.handleLoadConfig();
                    this.closeMapping();
                    this.props.addNotification(
                        "error",
                        cockpit.format(_("Error replacing SASL Mapping - $0"), errMsg.desc)
                    );
                });
    }

    deleteMapping() {
        // Start spinning
        const new_mappings = this.state.mappings;
        for (const saslMap of new_mappings) {
            if (saslMap.cn[0] === this.state.saslMapName) {
                saslMap.nssaslmapregexstring = [<Spinner className="ds-lower-field" key={new_mappings[0].nssaslmapregexstring[0]} loading size="sm" />];
                saslMap.nssaslmapbasedntemplate = [<Spinner className="ds-lower-field" key={new_mappings[0].nssaslmapbasedntemplate[0]} loading size="sm" />];
                saslMap.nssaslmapfiltertemplate = [<Spinner className="ds-lower-field" key={new_mappings[0].nssaslmapfiltertemplate[0]} loading size="sm" />];
                saslMap.nssaslmappriority = [<Spinner className="ds-lower-field" key={new_mappings[0].nssaslmappriority[0]} loading size="sm" />];
            }
        }
        this.setState({
            mappings: new_mappings,
            tableLoading: true
        });

        const cmd = [
            'dsconf', '-j', "ldapi://%2fvar%2frun%2fslapd-" + this.props.serverId + ".socket",
            'sasl', 'delete', this.state.saslMapName
        ];
        log_cmd("deleteMapping", "Delete sasl mapping", cmd);
        cockpit
                .spawn(cmd, { superuser: true, err: "message" })
                .done(content => {
                    this.handleLoadConfig();
                    this.props.addNotification(
                        "success",
                        _("Successfully deleted SASL Mapping")
                    );
                })
                .fail(err => {
                    const errMsg = JSON.parse(err);
                    this.handleLoadConfig();
                    this.closeConfirmDelete();
                    this.props.addNotification(
                        "error",
                        cockpit.format(_("Error deleting SASL Mapping - $0"), errMsg.desc)
                    );
                });
    }

    handleSaveConfig() {
        // Start spinning
        this.setState({
            configLoading: true,
        });

        // Build up the command list
        const cmd = [
            'dsconf', '-j', "ldapi://%2fvar%2frun%2fslapd-" + this.props.serverId + ".socket", 'config'
        ];

        const mech_str_new = this.state.allowedMechs.join(' ');
        const mech_str_orig = this.state._allowedMechs.join(' ');
        if (mech_str_orig !== mech_str_new) {
            if (mech_str_new.length === 0) {
                cmd.push('delete');
                cmd.push("nsslapd-allowed-sasl-mechanisms");
            } else {
                cmd.push('replace');
                cmd.push("nsslapd-allowed-sasl-mechanisms=" + mech_str_new);
            }
        } else {
            // The rest of the settings always have values to replace
            cmd.push('replace');
        }
        if (this.state._mappingFallback !== this.state.mappingFallback) {
            let value = "off";
            if (this.state.mappingFallback) {
                value = "on";
            }
            cmd.push("nsslapd-sasl-mapping-fallback=" + value);
        }
        if (this.state._maxBufSize !== this.state.maxBufSize) {
            cmd.push("nsslapd-sasl-max-buffer-size=" + this.state.maxBufSize);
        }

        log_cmd("handleSaveConfig", "Applying SASL config change", cmd);
        cockpit
                .spawn(cmd, { superuser: true, err: "message" })
                .done(content => {
                    this.handleLoadConfig();
                    this.props.addNotification(
                        "warning",
                        _("Successfully updated SASL configuration.  These changes require the server to be restarted to take effect.")
                    );
                })
                .fail(err => {
                    const errMsg = JSON.parse(err);
                    this.handleLoadConfig();
                    this.props.addNotification(
                        "error",
                        cockpit.format(_("Error updating SASL configuration - $0"), errMsg.desc)
                    );
                });
    }

    render() {
        let body = "";
        let saveBtnName = _("Save Settings");
        const extraPrimaryProps = {};
        if (this.state.configLoading) {
            saveBtnName = _("Saving settings ...");
            extraPrimaryProps.spinnerAriaValueText = _("Saving");
        }

        if (!this.state.loaded) {
            body = (
                <div className="ds-loading-spinner ds-margin-top-xlg ds-center">
                    <TextContent>
                        <Text component={TextVariants.h3}>{_("Loading SASL Configuration ...")}</Text>
                    </TextContent>
                    <Spinner className="ds-margin-top" size="lg" />
                </div>
            );
        } else {
            body = (
                <div className={this.state.configLoading ? "ds-disabled ds-margin-bottom-md" : "ds-margin-bottom-md"}>
                    <Grid>
                        <GridItem span={3}>
                            <TextContent>
                                <Text component={TextVariants.h3}>
                                    {_("SASL Settings")}
                                    <Button 
                                        variant="plain"
                                        aria-label={_("Refresh SASL settings")}
                                        onClick={this.handleLoadConfig}
                                    >
                                        <SyncAltIcon />
                                    </Button>
                                </Text>
                            </TextContent>
                        </GridItem>
                    </Grid>
                    <Form isHorizontal autoComplete="off" className="ds-left-margin">
                        <Grid title={_("The maximum SASL buffer size in bytes (nsslapd-sasl-max-buffer-size).")} className="ds-margin-top-xlg">
                            <GridItem className="ds-label" span={3}>
                                {_("Max SASL Buffer Size")}
                            </GridItem>
                            <GridItem span={9}>
                                <TextInput
                                    value={this.state.maxBufSize}
                                    type="number"
                                    id="maxBufSize"
                                    aria-describedby="horizontal-form-name-helper"
                                    name="maxBufSize"
                                    onChange={(e, str) => {
                                        this.handleChange(e);
                                    }}
                                />
                            </GridItem>
                        </Grid>
                        <Grid
                            title={_("A list of SASL mechanisms the server will only accept (nsslapd-allowed-sasl-mechanisms).  The default is all mechanisms are allowed.")}
                        >
                            <GridItem className="ds-label" span={3}>
                                {_("Allowed SASL Mechanisms")}
                            </GridItem>
                            <GridItem span={9}>
                                <Select
                                    variant={SelectVariant.typeaheadMulti}
                                    typeAheadAriaLabel="Type SASL mechanism to allow"
                                    onToggle={(event, isOpen) => this.handleOnAllowedMechToggle(event, isOpen)}
                                    onSelect={this.handleOnSelect}
                                    onClear={this.handleOnAllowedMechClear}
                                    selections={this.state.allowedMechs}
                                    isOpen={this.state.isAllowedMechOpen}
                                    aria-labelledby="typeAhead-sasl-mechs"
                                    placeholderText={_("Type SASL mechanism to allow...")}
                                    noResultsFoundText="There are no matching entries"
                                >
                                    {this.state.supportedMechs.map((attr, index) => (
                                        <SelectOption
                                            key={index}
                                            value={attr}
                                        />
                                    ))}
                                </Select>
                            </GridItem>
                        </Grid>
                        <Grid
                            title={_("Check all sasl mappings until one succeeds or they all fail (nsslapd-sasl-mapping-fallback).")}
                        >
                            <Checkbox
                                isChecked={this.state.mappingFallback}
                                id="mappingFallback"
                                onChange={(e, checked) => {
                                    this.handleChange(e);
                                }}
                                label={_("Allow SASL Mapping Fallback")}
                            />
                        </Grid>
                    </Form>
                    <Button
                        isDisabled={this.state.saveDisabled || this.state.configLoading}
                        variant="primary"
                        className="ds-margin-top-xlg"
                        onClick={this.handleSaveConfig}
                        isLoading={this.state.configLoading}
                        spinnerAriaValueText={this.state.configLoading ? _("Saving") : undefined}
                        {...extraPrimaryProps}
                    >
                        {saveBtnName}
                    </Button>
                    <hr />
                    <Grid
                        title={_("A list of SASL mechanisms the server will only accept (nsslapd-allowed-sasl-mechanisms).  The default is all mechanisms are allowed.")}
                        className="ds-margin-top"
                    >
                        <TextContent>
                            <Text className="ds-center ds-margin-top" component={TextVariants.h3}>
                                {_("SASL Mappings")}
                            </Text>
                        </TextContent>
                    </Grid>
                    <SASLTable
                        key={this.state.mappingKey}
                        rows={this.state.mappings}
                        editMapping={this.showEditMapping}
                        deleteMapping={this.showConfirmDelete}
                        className="ds-margin-top"
                    />
                    <Button
                        variant="primary"
                        onClick={this.handleShowCreateMapping}
                    >
                        {_("Create New Mapping")}
                    </Button>
                </div>
            );
        }

        return (
            <div id="server-sasl-page">
                {body}
                <SASLMappingModal
                    showModal={this.state.showMappingModal}
                    testBtnDisabled={this.state.testBtnDisabled}
                    saveDisabled={this.state.saveMappingDisabled}
                    handleClose={this.closeMapping}
                    handleChange={this.onModalChange}
                    handleTestRegex={this.onTestRegex}
                    saveHandler={this.state.saslModalType === "Create" ? this.createMapping : this.editMapping}
                    error={this.state.saslErrObj}
                    type={this.state.saslModalType}
                    name={this.state.saslMapName}
                    regex={this.state.saslMapRegex}
                    testText={this.state.saslTestText}
                    base={this.state.saslBase}
                    filter={this.state.saslFilter}
                    priority={this.state.saslPriority}
                    spinning={this.state.tableLoading}
                />
                <DoubleConfirmModal
                    showModal={this.state.showConfirmDelete}
                    closeHandler={this.closeConfirmDelete}
                    handleChange={this.onModalChange}
                    actionHandler={this.deleteMapping}
                    item={this.state.saslMapName}
                    checked={this.state.modalChecked}
                    spinning={this.state.tableLoading}
                    mTitle={_("Delete SASL Mapping")}
                    mMsg={_("Are you sure you want to delete this SASL mapping?")}
                    mSpinningMsg={_("Deleting SASL Mapping ...")}
                    mBtnName={_("Delete Mapping")}
                />
            </div>
        );
    }
}
