import cockpit from "cockpit";
import React from "react";
import {
    Row,
    Col,
    Form,
    FormGroup,
    FormControl,
    ControlLabel
} from "patternfly-react";
import {
    Button,
    Checkbox,
    // Form,
    // FormGroup,
    Modal,
    ModalVariant,
    Select,
    SelectVariant,
    SelectOption,
    // TextInput,
    noop
} from "@patternfly/react-core";
import PropTypes from "prop-types";
import PluginBasicConfig from "./pluginBasicConfig.jsx";
import { log_cmd } from "../tools.jsx";

class MemberOf extends React.Component {
    componentDidMount(prevProps) {
        if (this.props.wasActiveList.includes(5)) {
            if (this.state.firstLoad) {
                this.getObjectClasses();
                this.getAttributes();
                this.updateFields();
            }
        }
    }

    componentDidUpdate(prevProps) {
        if (this.props.rows !== prevProps.rows) {
            this.updateFields();
        }
    }

    constructor(props) {
        super(props);

        this.getObjectClasses = this.getObjectClasses.bind(this);
        this.getAttributes = this.getAttributes.bind(this);
        this.updateFields = this.updateFields.bind(this);
        this.handleFieldChange = this.handleFieldChange.bind(this);
        this.handleCheckboxChange = this.handleCheckboxChange.bind(this);
        this.openModal = this.openModal.bind(this);
        this.closeModal = this.closeModal.bind(this);
        this.addConfig = this.addConfig.bind(this);
        this.editConfig = this.editConfig.bind(this);
        this.deleteConfig = this.deleteConfig.bind(this);
        this.cmdOperation = this.cmdOperation.bind(this);
        this.runFixup = this.runFixup.bind(this);
        this.toggleFixupModal = this.toggleFixupModal.bind(this);

        this.state = {
            firstLoad: true,
            objectClasses: [],
            attributeTypes: [],

            memberOfAttr: [],
            memberOfAttrOptions: [],
            memberOfGroupAttr: [],
            memberOfGroupAttrOptions: [],
            memberOfEntryScope: "",
            memberOfEntryScopeExcludeSubtree: "",
            memberOfAutoAddOC: [],
            memberOfAutoAddOCOptions: [],
            memberOfAllBackends: false,
            memberOfSkipNested: false,
            memberOfConfigEntry: "",
            configEntryModalShow: false,
            fixupModalShow: false,

            configDN: "",
            configAttr: [],
            configAttrOptions: [],
            configGroupAttr: [],
            configGroupAttrOptions: [],
            configEntryScope: "",
            configEntryScopeExcludeSubtree: "",
            configAutoAddOC: [],
            configAutoAddOCOptions: [],
            configAllBackends: false,
            configSkipNested: false,
            newEntry: true,

            fixupDN: "",
            fixupFilter: "",

            isConfigAttrOpen: false,
            isConfigGroupAttrOpen: false,
            isConfigAutoAddOCOpen: false,
            isMemberOfAttrOpen: false,
            isMemberOfGroupAttrOpen: false,
            isMemberOfAutoAddOCOpen: false,

        };

        // Config Attribute
        this.onConfigAttrSelect = (event, selection) => {
            if (this.state.configAttr.includes(selection)) {
                this.setState(
                    (prevState) => ({
                        configAttr: prevState.configAttr.filter((item) => item !== selection),
                        isConfigAttrOpen: false
                    }),
                );
            } else {
                this.setState(
                    (prevState) => ({
                        configAttr: [...prevState.configAttr, selection],
                        isConfigAttrOpen: false
                    }),
                );
            }
        };
        this.onConfigAttrToggle = isConfigAttrOpen => {
            this.setState({
                isConfigAttrOpen
            });
        };
        this.onConfigAttrClear = () => {
            this.setState({
                configAttr: [],
                isConfigAttrOpen: false
            });
        };
        this.onConfigAttrCreateOption = newValue => {
            if (!this.state.configAttrOptions.includes(newValue)) {
                this.setState({
                    configAttrOptions: [...this.state.configAttrOptions, newValue],
                    isConfigAttrOpen: false
                });
            }
        };

        // Config Group Attribute
        this.onConfigGroupAttrSelect = (event, selection) => {
            if (this.state.configGroupAttr.includes(selection)) {
                this.setState(
                    (prevState) => ({
                        configGroupAttr: prevState.configGroupAttr.filter((item) => item !== selection),
                        isConfigGroupAttrOpen: false
                    }),
                );
            } else {
                this.setState(
                    (prevState) => ({
                        configGroupAttr: [...prevState.configGroupAttr, selection],
                        isConfigGroupAttrOpen: false
                    }),
                );
            }
        };
        this.onConfigGroupAttrToggle = isConfigGroupAttrOpen => {
            this.setState({
                isConfigGroupAttrOpen
            });
        };
        this.onConfigGroupAttrClear = () => {
            this.setState({
                configGroupAttr: [],
                isConfigGroupAttrOpen: false
            });
        };
        this.onConfigGroupAttrCreateOption = newValue => {
            if (!this.state.configGroupAttrOptions.includes(newValue)) {
                this.setState({
                    configGroupAttrOptions: [...this.state.configGroupAttrOptions, newValue],
                    isConfigGroupAttrOpen: false
                });
            }
        };

        // Config Auto Add OC
        this.onConfigAutoAddOCSelect = (event, selection) => {
            if (this.state.configAutoAddOC.includes(selection)) {
                this.setState(
                    (prevState) => ({
                        configAutoAddOC: prevState.configAutoAddOC.filter((item) => item !== selection),
                        isConfigAutoAddOCOpen: false
                    }),
                );
            } else {
                this.setState(
                    (prevState) => ({
                        configAutoAddOC: [...prevState.configAutoAddOC, selection],
                        isConfigAutoAddOCOpen: false
                    }),
                );
            }
        };
        this.onConfigAutoAddOCToggle = isConfigAutoAddOCOpen => {
            this.setState({
                isConfigAutoAddOCOpen
            });
        };
        this.onConfigAutoAddOCClear = () => {
            this.setState({
                configAutoAddOC: [],
                isConfigAutoAddOCOpen: false
            });
        };
        this.onConfigAutoAddOCCreateOption = newValue => {
            if (!this.state.configAutoAddOCOptions.includes(newValue)) {
                this.setState({
                    configAutoAddOCOptions: [...this.state.configAutoAddOCOptions, newValue],
                    isConfigAutoAddOCOpen: false
                });
            }
        };

        // MemberOr Attribute
        this.onMemberOfAttrSelect = (event, selection) => {
            if (this.state.memberOfAttr.includes(selection)) {
                this.setState(
                    (prevState) => ({
                        memberOfAttr: prevState.memberOfAttr.filter((item) => item !== selection),
                        isMemberOfAttrOpen: false
                    }),
                );
            } else {
                this.setState(
                    (prevState) => ({
                        memberOfAttr: [...prevState.memberOfAttr, selection],
                        isMemberOfAttrOpen: false
                    }),
                );
            }
        };
        this.onMemberOfAttrToggle = isMemberOfAttrOpen => {
            this.setState({
                isMemberOfAttrOpen
            });
        };
        this.onMemberOfAttrClear = () => {
            this.setState({
                memberOfAttr: [],
                isMemberOfAttrOpen: false
            });
        };
        this.onMemberOfAttrCreateOption = newValue => {
            if (!this.state.memberOfAttrOptions.includes(newValue)) {
                this.setState({
                    memberOfAttrOptions: [...this.state.memberOfAttrOptions, newValue],
                    isMemberOfAttrOpen: false
                });
            }
        };

        // MemberOr Group Attribute
        this.onMemberOfGroupAttrSelect = (event, selection) => {
            if (this.state.memberOfGroupAttr.includes(selection)) {
                this.setState(
                    (prevState) => ({
                        memberOfGroupAttr: prevState.memberOfGroupAttr.filter((item) => item !== selection),
                        isMemberOfGroupAttrOpen: false
                    }),
                );
            } else {
                this.setState(
                    (prevState) => ({
                        memberOfGroupAttr: [...prevState.memberOfGroupAttr, selection],
                        isMemberOfGroupAttrOpen: false
                    }),
                );
            }
        };
        this.onMemberOfGroupAttrToggle = isMemberOfGroupAttrOpen => {
            this.setState({
                isMemberOfGroupAttrOpen
            });
        };
        this.onMemberOfGroupAttrClear = () => {
            this.setState({
                memberOfGroupAttr: [],
                isMemberOfGroupAttrOpen: false
            });
        };
        this.onMemberOfGroupAttrCreateOption = newValue => {
            if (!this.state.memberOfGroupAttrOptions.includes(newValue)) {
                this.setState({
                    memberOfGroumemberOfGroupAttrOptionspAttr: [...this.state.memberOfGroupAttrOptions, newValue],
                    isMemberOfGroupAttrOpen: false
                });
            }
        };

        // MemberOr Auto Add OC
        this.onMemberOfAutoAddOCSelect = (event, selection) => {
            if (this.state.memberOfAutoAddOC.includes(selection)) {
                this.setState(
                    (prevState) => ({
                        memberOfAutoAddOC: prevState.memberOfAutoAddOC.filter((item) => item !== selection),
                        isMemberOfAutoAddOCOpen: false
                    }),
                );
            } else {
                this.setState(
                    (prevState) => ({
                        memberOfAutoAddOC: [...prevState.memberOfAutoAddOC, selection],
                        isMemberOfAutoAddOCOpen: false
                    }),
                );
            }
        };
        this.onMemberOfAutoAddOCToggle = isMemberOfAutoAddOCOpen => {
            this.setState({
                isMemberOfAutoAddOCOpen
            });
        };
        this.onMemberOfAutoAddOCClear = () => {
            this.setState({
                memberOfAutoAddOC: [],
                isMemberOfAutoAddOCOpen: false
            });
        };
        this.onMemberOfAutoAddOCCreateOption = newValue => {
            if (!this.state.memberOfAutoAddOCOptions.includes(newValue)) {
                this.setState({
                    memberOfAutoAddOCOptions: [...this.state.memberOfAutoAddOCOptions, newValue],
                    isMemberOfAutoAddOCOpen: false
                });
            }
        };
    }

    toggleFixupModal() {
        this.setState(prevState => ({
            fixupModalShow: !prevState.fixupModalShow,
            fixupDN: "",
            fixupFilter: ""
        }));
    }

    runFixup() {
        if (!this.state.fixupDN) {
            this.props.addNotification("warning", "Fixup DN is required.");
        } else {
            let cmd = [
                "dsconf",
                "-j",
                "ldapi://%2fvar%2frun%2fslapd-" + this.props.serverId + ".socket",
                "plugin",
                "memberof",
                "fixup",
                this.state.fixupDN
            ];

            if (this.state.fixupFilter) {
                cmd = [...cmd, "--filter", this.state.fixupFilter];
            }

            this.props.toggleLoadingHandler();
            log_cmd("runFixup", "Run fixup MemberOf Plugin ", cmd);
            cockpit
                    .spawn(cmd, {
                        superuser: true,
                        err: "message"
                    })
                    .done(content => {
                        this.props.addNotification(
                            "success",
                            `Fixup task for ${this.state.fixupDN} was successfull`
                        );
                        this.props.toggleLoadingHandler();
                        this.setState({
                            fixupModalShow: false
                        });
                    })
                    .fail(err => {
                        let errMsg = JSON.parse(err);
                        this.props.addNotification(
                            "error",
                            `Fixup task for ${this.state.fixupDN} has failed ${errMsg.desc}`
                        );
                        this.props.toggleLoadingHandler();
                        this.setState({
                            fixupModalShow: false
                        });
                    });
        }
    }

    openModal() {
        this.getObjectClasses();
        this.getAttributes();
        if (!this.state.memberOfConfigEntry) {
            this.setState({
                configEntryModalShow: true,
                newEntry: true,
                configDN: "",
                configAttr: [],
                configGroupAttr: [],
                configEntryScope: "",
                configEntryScopeExcludeSubtree: "",
                configAutoAddOC: [],
                configAllBackends: false,
                configSkipNested: false
            });
        } else {
            let configAttrObjectList = [];
            let configGroupAttrObjectList = [];
            let cmd = [
                "dsconf",
                "-j",
                "ldapi://%2fvar%2frun%2fslapd-" + this.props.serverId + ".socket",
                "plugin",
                "memberof",
                "config-entry",
                "show",
                this.state.memberOfConfigEntry
            ];

            this.props.toggleLoadingHandler();
            log_cmd("openMemberOfModal", "Fetch the MemberOf Plugin config entry", cmd);
            cockpit
                    .spawn(cmd, {
                        superuser: true,
                        err: "message"
                    })
                    .done(content => {
                        let configEntry = JSON.parse(content).attrs;
                        this.setState({
                            configEntryModalShow: true,
                            newEntry: false,
                            configDN: this.state.memberOfConfigEntry,
                            configAutoAddOC:
                            configEntry["memberofautoaddoc"] === undefined
                                ? []
                                : [configEntry["memberofautoaddoc"][0]],
                            configAllBackends: !(
                                configEntry["memberofallbackends"] === undefined ||
                            configEntry["memberofallbackends"][0] == "off"
                            ),
                            configSkipNested: !(
                                configEntry["memberofskipnested"] === undefined ||
                            configEntry["memberofskipnested"][0] == "off"
                            ),
                            configConfigEntry:
                            configEntry["nsslapd-pluginConfigArea"] === undefined
                                ? ""
                                : configEntry["nsslapd-pluginConfigArea"][0],
                            configEntryScope:
                            configEntry["memberofentryscope"] === undefined
                                ? ""
                                : configEntry["memberofentryscope"][0],
                            configEntryScopeExcludeSubtree:
                            configEntry["memberofentryscopeexcludesubtree"] === undefined
                                ? ""
                                : configEntry["memberofentryscopeexcludesubtree"][0]
                        });
                        if (configEntry["memberofattr"] === undefined) {
                            this.setState({ configAttr: [] });
                        } else {
                            for (let value of configEntry["memberofattr"]) {
                                configAttrObjectList = [...configAttrObjectList, value];
                            }
                            this.setState({ configAttr: configAttrObjectList });
                        }
                        if (configEntry["memberofgroupattr"] === undefined) {
                            this.setState({ configGroupAttr: [] });
                        } else {
                            for (let value of configEntry["memberofgroupattr"]) {
                                configGroupAttrObjectList = [...configGroupAttrObjectList, value];
                            }
                            this.setState({
                                configGroupAttr: configGroupAttrObjectList
                            });
                        }
                        this.props.toggleLoadingHandler();
                    })
                    .fail(_ => {
                        this.setState({
                            configEntryModalShow: true,
                            newEntry: true,
                            configDN: this.state.memberOfConfigEntry,
                            configAttr: [],
                            configGroupAttr: [],
                            configEntryScope: "",
                            configEntryScopeExcludeSubtree: "",
                            configAutoAddOC: [],
                            configAllBackends: false,
                            configSkipNested: false
                        });
                        this.props.toggleLoadingHandler();
                    });
        }
    }

    closeModal() {
        this.setState({ configEntryModalShow: false });
    }

    cmdOperation(action) {
        const {
            configDN,
            configAttr,
            configGroupAttr,
            configEntryScope,
            configEntryScopeExcludeSubtree,
            configAutoAddOC,
            configAllBackends,
            configSkipNested
        } = this.state;

        if (configAttr.length == 0 || configGroupAttr.length == 0) {
            this.props.addNotification(
                "warning",
                "Config Attribute and Group Attribute are required."
            );
        } else {
            let cmd = [
                "dsconf",
                "-j",
                "ldapi://%2fvar%2frun%2fslapd-" + this.props.serverId + ".socket",
                "plugin",
                "memberof",
                "config-entry",
                action,
                configDN,
                "--scope",
                configEntryScope || action == "add" ? configEntryScope : "delete",
                "--exclude",
                configEntryScopeExcludeSubtree || action == "add"
                    ? configEntryScopeExcludeSubtree
                    : "delete",
                "--allbackends",
                configAllBackends ? "on" : "off",
                "--skipnested",
                configSkipNested ? "on" : "off"
            ];

            cmd = [...cmd, "--autoaddoc"];
            if (configAutoAddOC.length != 0) {
                cmd = [...cmd, configAutoAddOC[0]];
            } else if (action == "add") {
                cmd = [...cmd, ""];
            } else {
                cmd = [...cmd, "delete"];
            }

            // Delete attributes if the user set an empty value to the field
            cmd = [...cmd, "--attr"];
            if (configAttr.length != 0) {
                for (let value of configAttr) {
                    cmd = [...cmd, value];
                }
            }
            cmd = [...cmd, "--groupattr"];
            if (configGroupAttr.length != 0) {
                for (let value of configGroupAttr) {
                    cmd = [...cmd, value];
                }
            }

            this.props.toggleLoadingHandler();
            log_cmd("memberOfOperation", `Do the ${action} operation on the MemberOf Plugin`, cmd);
            cockpit
                    .spawn(cmd, {
                        superuser: true,
                        err: "message"
                    })
                    .done(content => {
                        console.info("memberOfOperation", "Result", content);
                        this.props.addNotification(
                            "success",
                            `Config entry ${configDN} was successfully ${action}ed`
                        );
                        this.props.pluginListHandler();
                        this.closeModal();
                        this.props.toggleLoadingHandler();
                    })
                    .fail(err => {
                        let errMsg = JSON.parse(err);
                        this.props.addNotification(
                            "error",
                            `Error during the config entry ${action} operation - ${errMsg.desc}`
                        );
                        this.props.pluginListHandler();
                        this.closeModal();
                        this.props.toggleLoadingHandler();
                    });
        }
    }

    deleteConfig() {
        let cmd = [
            "dsconf",
            "-j",
            "ldapi://%2fvar%2frun%2fslapd-" + this.props.serverId + ".socket",
            "plugin",
            "memberof",
            "config-entry",
            "delete",
            this.state.configDN
        ];

        this.props.toggleLoadingHandler();
        log_cmd("deleteConfig", "Delete the MemberOf Plugin config entry", cmd);
        cockpit
                .spawn(cmd, {
                    superuser: true,
                    err: "message"
                })
                .done(content => {
                    console.info("deleteConfig", "Result", content);
                    this.props.addNotification(
                        "success",
                        `Config entry ${this.state.configDN} was successfully deleted`
                    );
                    this.props.pluginListHandler();
                    this.closeModal();
                    this.props.toggleLoadingHandler();
                })
                .fail(err => {
                    let errMsg = JSON.parse(err);
                    this.props.addNotification(
                        "error",
                        `Error during the config entry removal operation - ${errMsg.desc}`
                    );
                    this.props.pluginListHandler();
                    this.closeModal();
                    this.props.toggleLoadingHandler();
                });
    }

    addConfig() {
        this.cmdOperation("add");
    }

    editConfig() {
        this.cmdOperation("set");
    }

    handleCheckboxChange(checked, e) {
        this.setState({
            [e.target.id]: checked
        });
    }

    handleFieldChange(e) {
        this.setState({
            [e.target.id]: e.target.value
        });
    }

    updateFields() {
        let memberOfAttrObjectList = [];
        let memberOfGroupAttrObjectList = [];

        if (this.props.rows.length > 0) {
            const pluginRow = this.props.rows.find(row => row.cn[0] === "MemberOf Plugin");

            this.setState({
                memberOfAutoAddOC:
                    pluginRow["memberofautoaddoc"] === undefined
                        ? []
                        : [pluginRow["memberofautoaddoc"][0]],
                memberOfAllBackends: !(
                    pluginRow["memberofallbackends"] === undefined ||
                    pluginRow["memberofallbackends"][0] == "off"
                ),
                memberOfSkipNested: !(
                    pluginRow["memberofskipnested"] === undefined ||
                    pluginRow["memberofskipnested"][0] == "off"
                ),
                memberOfConfigEntry:
                    pluginRow["nsslapd-pluginConfigArea"] === undefined
                        ? ""
                        : pluginRow["nsslapd-pluginConfigArea"][0],
                memberOfEntryScope:
                    pluginRow["memberofentryscope"] === undefined
                        ? ""
                        : pluginRow["memberofentryscope"][0],
                memberOfEntryScopeExcludeSubtree:
                    pluginRow["memberofentryscopeexcludesubtree"] === undefined
                        ? ""
                        : pluginRow["memberofentryscopeexcludesubtree"][0]
            });
            if (pluginRow["memberofattr"] === undefined) {
                this.setState({ memberOfAttr: [] });
            } else {
                for (let value of pluginRow["memberofattr"]) {
                    memberOfAttrObjectList = [...memberOfAttrObjectList, value];
                }
                this.setState({ memberOfAttr: memberOfAttrObjectList });
            }
            if (pluginRow["memberofgroupattr"] === undefined) {
                this.setState({ memberOfGroupAttr: [] });
            } else {
                for (let value of pluginRow["memberofgroupattr"]) {
                    memberOfGroupAttrObjectList = [...memberOfGroupAttrObjectList, value];
                }
                this.setState({
                    memberOfGroupAttr: memberOfGroupAttrObjectList
                });
            }
        }
    }

    getObjectClasses() {
        this.setState({
            firstLoad: false
        });
        const oc_cmd = [
            "dsconf",
            "-j",
            "ldapi://%2fvar%2frun%2fslapd-" + this.props.serverId + ".socket",
            "schema",
            "objectclasses",
            "list"
        ];
        log_cmd("getObjectClasses", "Get objectClasses", oc_cmd);
        cockpit
                .spawn(oc_cmd, { superuser: true, err: "message" })
                .done(content => {
                    const ocContent = JSON.parse(content);
                    let ocs = [];
                    for (let content of ocContent["items"]) {
                        ocs.push(content.name[0]);
                    }
                    this.setState({
                        objectClasses: ocs
                    });
                })
                .fail(err => {
                    let errMsg = JSON.parse(err);
                    this.props.addNotification("error", `Failed to get objectClasses - ${errMsg.desc}`);
                });
    }

    getAttributes() {
        const oc_cmd = [
            "dsconf",
            "-j",
            "ldapi://%2fvar%2frun%2fslapd-" + this.props.serverId + ".socket",
            "schema",
            "attributetypes",
            "list"
        ];
        log_cmd("getAttributes", "Get getAttributes", oc_cmd);
        cockpit
                .spawn(oc_cmd, { superuser: true, err: "message" })
                .done(content => {
                    const atContent = JSON.parse(content);
                    let attrs = [];
                    for (let content of atContent["items"]) {
                        attrs.push(content.name[0]);
                    }
                    this.setState({
                        attributeTypes: attrs
                    });
                })
                .fail(err => {
                    let errMsg = JSON.parse(err);
                    this.props.addNotification("error", `Failed to get attributes - ${errMsg.desc}`);
                });
    }

    render() {
        const {
            objectClasses,
            attributeTypes,
            memberOfAttr,
            memberOfGroupAttr,
            memberOfEntryScope,
            memberOfEntryScopeExcludeSubtree,
            memberOfAutoAddOC,
            memberOfAllBackends,
            memberOfSkipNested,
            memberOfConfigEntry,
            configDN,
            configEntryModalShow,
            configAttr,
            configGroupAttr,
            configEntryScope,
            configEntryScopeExcludeSubtree,
            configAutoAddOC,
            configAllBackends,
            configSkipNested,
            newEntry,
            fixupModalShow,
            fixupDN,
            fixupFilter,

        } = this.state;

        let specificPluginCMD = [
            "dsconf",
            "-j",
            "ldapi://%2fvar%2frun%2fslapd-" + this.props.serverId + ".socket",
            "plugin",
            "memberof",
            "set",
            "--scope",
            memberOfEntryScope || "delete",
            "--exclude",
            memberOfEntryScopeExcludeSubtree || "delete",
            "--config-entry",
            memberOfConfigEntry || "delete",
            "--allbackends",
            memberOfAllBackends ? "on" : "off",
            "--skipnested",
            memberOfSkipNested ? "on" : "off"
        ];

        specificPluginCMD = [...specificPluginCMD, "--autoaddoc"];
        if (memberOfAutoAddOC.length != 0) {
            specificPluginCMD = [...specificPluginCMD, memberOfAutoAddOC[0]];
        } else {
            specificPluginCMD = [...specificPluginCMD, "delete"];
        }

        // Delete attributes if the user set an empty value to the field
        specificPluginCMD = [...specificPluginCMD, "--attr"];
        if (memberOfAttr.length != 0) {
            for (let value of memberOfAttr) {
                specificPluginCMD = [...specificPluginCMD, value];
            }
        } else {
            specificPluginCMD = [...specificPluginCMD, "delete"];
        }

        specificPluginCMD = [...specificPluginCMD, "--groupattr"];
        if (memberOfGroupAttr.length != 0) {
            for (let value of memberOfGroupAttr) {
                specificPluginCMD = [...specificPluginCMD, value];
            }
        } else {
            specificPluginCMD = [...specificPluginCMD, "delete"];
        }

        return (
            <div>
                <Modal
                    variant={ModalVariant.small}
                    aria-labelledby="ds-modal"
                    title="Fixup MemberOf Task"
                    isOpen={fixupModalShow}
                    onClose={this.toggleFixupModal}
                    actions={[
                        <Button key="confirm" variant="primary" onClick={this.runFixup}>
                            Run
                        </Button>,
                        <Button key="cancel" variant="link" onClick={this.toggleFixupModal}>
                            Cancel
                        </Button>
                    ]}
                >
                    <Row>
                        <Col sm={12}>
                            <Form horizontal>
                                <FormGroup controlId="fixupDN" key="fixupDN">
                                    <Col sm={3}>
                                        <ControlLabel title="Base DN that contains entries to fix up">
                                            Base DN
                                        </ControlLabel>
                                    </Col>
                                    <Col sm={9}>
                                        <FormControl
                                            type="text"
                                            value={fixupDN}
                                            onChange={this.handleFieldChange}
                                        />
                                    </Col>
                                </FormGroup>
                                <FormGroup controlId="fixupFilter" key="fixupFilter">
                                    <Col sm={3}>
                                        <ControlLabel title="Filter for entries to fix up. If omitted, all entries with objectclass inetuser/inetadmin/nsmemberof under the specified base will have their memberOf attribute regenerated.">
                                            Filter DN
                                        </ControlLabel>
                                    </Col>
                                    <Col sm={9}>
                                        <FormControl
                                            type="text"
                                            value={fixupFilter}
                                            onChange={this.handleFieldChange}
                                        />
                                    </Col>
                                </FormGroup>
                            </Form>
                        </Col>
                    </Row>
                </Modal>
                <Modal
                    variant={ModalVariant.medium}
                    aria-labelledby="ds-modal"
                    title="Manage MemberOf Plugin Shared Config Entry"
                    isOpen={configEntryModalShow}
                    onClose={this.closeModal}
                    actions={[
                        <Button key="delete" variant="primary" onClick={this.deleteConfig} isDisabled={newEntry}>
                            Delete
                        </Button>,
                        <Button key="save" variant="primary" onClick={this.editConfig} isDisabled={newEntry}>
                            Save
                        </Button>,
                        <Button key="add" variant="primary" onClick={this.addConfig} isDisabled={!newEntry}>
                            Add
                        </Button>,
                        <Button key="cancel" variant="link" onClick={this.closeModal}>
                            Cancel
                        </Button>
                    ]}
                >
                    <Row>
                        <Col sm={12}>
                            <Form horizontal>
                                <FormGroup controlId="configDN">
                                    <Col componentClass={ControlLabel} title="The config entry full DN" sm={3}>
                                        Config DN
                                    </Col>
                                    <Col sm={9}>
                                        <FormControl
                                            type="text"
                                            value={configDN}
                                            onChange={this.handleFieldChange}
                                            disabled={!newEntry}
                                        />
                                    </Col>
                                </FormGroup>
                                <FormGroup
                                    key="configAttr"
                                    controlId="configAttr"
                                    disabled={false}
                                >
                                    <Col
                                        componentClass={ControlLabel}
                                        sm={3}
                                        title="Specifies the attribute in the user entry for the Directory Server to manage to reflect group membership (memberOfAttr)"
                                    >
                                        Attribute
                                    </Col>
                                    <Col sm={9}>
                                        <Select
                                            variant={SelectVariant.typeaheadMulti}
                                            typeAheadAriaLabel="Type a member attribute"
                                            onToggle={this.onConfigAttrToggle}
                                            onSelect={this.onConfigAttrSelect}
                                            onClear={this.onConfigAttrClear}
                                            selections={configAttr}
                                            isOpen={this.state.isConfigAttrOpen}
                                            aria-labelledby="typeAhead-config-attr"
                                            placeholderText="Type a member attribute..."
                                            noResultsFoundText="There are no matching entries"
                                            isCreatable
                                            onCreateOption={this.isConfigAttrOpen}
                                            >
                                            {["memberOf"].map((attr, index) => (
                                                <SelectOption
                                                    key={index}
                                                    value={attr}
                                                />
                                                ))}
                                        </Select>
                                    </Col>
                                </FormGroup>
                                <FormGroup
                                    key="configGroupAttr"
                                    controlId="configGroupAttr"
                                    disabled={false}
                                >
                                    <Col
                                        componentClass={ControlLabel}
                                        sm={3}
                                        title="Specifies the attribute in the group entry to use to identify the DNs of group members (memberOfGroupAttr)"
                                    >
                                        Group Attribute
                                    </Col>
                                    <Col sm={9}>
                                        <Select
                                            variant={SelectVariant.typeaheadMulti}
                                            typeAheadAriaLabel="Type a member group attribute"
                                            onToggle={this.onConfigGroupAttrToggle}
                                            onSelect={this.onConfigGroupAttrSelect}
                                            onClear={this.onConfigGroupAttrClear}
                                            selections={configGroupAttr}
                                            isOpen={this.state.isConfigGroupAttrOpen}
                                            aria-labelledby="typeAhead-config-group-attr"
                                            placeholderText="Type a member group attribute..."
                                            noResultsFoundText="There are no matching entries"
                                            isCreatable
                                            onCreateOption={this.onConfigGroupAttrCreateOption}
                                            >
                                            {attributeTypes.map((attr, index) => (
                                                <SelectOption
                                                    key={index}
                                                    value={attr}
                                                />
                                                ))}
                                        </Select>
                                    </Col>
                                </FormGroup>
                            </Form>
                        </Col>
                    </Row>
                    <Row>
                        <Col sm={12}>
                            <Form horizontal>
                                <FormGroup
                                    key="configEntryScope"
                                    controlId="configEntryScope"
                                    disabled={false}
                                >
                                    <Col
                                        componentClass={ControlLabel}
                                        sm={3}
                                        title="Specifies backends or multiple-nested suffixes for the MemberOf plug-in to work on (memberOfEntryScope)"
                                    >
                                        Entry Scope
                                    </Col>
                                    <Col sm={6}>
                                        <FormControl
                                            type="text"
                                            value={configEntryScope}
                                            onChange={this.handleFieldChange}
                                        />
                                    </Col>
                                    <Col sm={3}>
                                        <Checkbox
                                            id="configAllBackends"
                                            isChecked={configAllBackends}
                                            onChange={this.handleCheckboxChange}
                                            title="Specifies whether to search the local suffix for user entries on all available suffixes (memberOfAllBackends)"
                                            label="All Backends"
                                        />
                                    </Col>
                                </FormGroup>
                                <FormGroup
                                    key="configEntryScopeExcludeSubtree"
                                    controlId="configEntryScopeExcludeSubtree"
                                    disabled={false}
                                >
                                    <Col
                                        componentClass={ControlLabel}
                                        sm={3}
                                        title="Specifies backends or multiple-nested suffixes for the MemberOf plug-in to exclude (memberOfEntryScopeExcludeSubtree)"
                                    >
                                        Entry Scope Exclude Subtree
                                    </Col>
                                    <Col sm={6}>
                                        <FormControl
                                            type="text"
                                            value={configEntryScopeExcludeSubtree}
                                            onChange={this.handleFieldChange}
                                        />
                                    </Col>
                                    <Col sm={3}>
                                        <Checkbox
                                            id="configSkipNested"
                                            isChecked={configSkipNested}
                                            onChange={this.handleCheckboxChange}
                                            title="Specifies wherher to skip nested groups or not (memberOfSkipNested)"
                                            label="Skip Nested"
                                        />
                                    </Col>
                                </FormGroup>
                            </Form>
                        </Col>
                    </Row>
                    <Row>
                        <Col sm={12}>
                            <Form horizontal>
                                <FormGroup controlId="configAutoAddOC" disabled={false}>
                                    <Col componentClass={ControlLabel} sm={3} title="If an entry does not have an object class that allows the memberOf attribute then the memberOf plugin will automatically add the object class listed in the memberOfAutoAddOC parameter">
                                        Auto Add OC
                                    </Col>
                                    <Col sm={9}>
                                        <Select
                                            variant={SelectVariant.typeahead}
                                            typeAheadAriaLabel="Type an objectClass"
                                            onToggle={this.onConfigAutoAddOCToggle}
                                            onSelect={this.onConfigAutoAddOCSelect}
                                            onClear={this.onConfigAutoAddOCClear}
                                            selections={configAutoAddOC}
                                            isOpen={this.state.isConfigAutoAddOCOpen}
                                            aria-labelledby="typeAhead-config-auto-addoc"
                                            placeholderText="Type an objectClass..."
                                            noResultsFoundText="There are no matching entries"
                                            isCreatable
                                            onCreateOption={this.onConfigAutoAddOCCreateOption}
                                            >
                                            {objectClasses.map((attr, index) => (
                                                <SelectOption
                                                    key={index}
                                                    value={attr}
                                                />
                                                ))}
                                        </Select>
                                    </Col>
                                </FormGroup>
                            </Form>
                        </Col>
                    </Row>
                </Modal>

                <PluginBasicConfig
                    rows={this.props.rows}
                    serverId={this.props.serverId}
                    cn="MemberOf Plugin"
                    pluginName="MemberOf"
                    cmdName="memberof"
                    specificPluginCMD={specificPluginCMD}
                    savePluginHandler={this.props.savePluginHandler}
                    pluginListHandler={this.props.pluginListHandler}
                    addNotification={this.props.addNotification}
                    toggleLoadingHandler={this.props.toggleLoadingHandler}
                >
                    <Row>
                        <Col sm={12}>
                            <Form horizontal>
                                <FormGroup
                                    key="memberOfAttr"
                                    controlId="memberOfAttr"
                                    disabled={false}
                                >
                                    <Col
                                        componentClass={ControlLabel}
                                        sm={3}
                                        title="Specifies the attribute in the user entry for the Directory Server to manage to reflect group membership (memberOfAttr)"
                                    >
                                        Attribute
                                    </Col>
                                    <Col sm={8}>
                                        <Select
                                            variant={SelectVariant.typeaheadMulti}
                                            typeAheadAriaLabel="Type a member attribute"
                                            onToggle={this.onMemberOfAttrToggle}
                                            onSelect={this.onMemberOfAttrSelect}
                                            onClear={this.onMemberOfAttrClear}
                                            selections={memberOfAttr}
                                            isOpen={this.state.isMemberOfAttrOpen}
                                            aria-labelledby="typeAhead-memberof-attr"
                                            placeholderText="Type a member attribute..."
                                            noResultsFoundText="There are no matching entries"
                                            isCreatable
                                            onCreateOption={this.onMemberOfAttrCreateOption}
                                            >
                                            {["member", "memberCertificate", "uniqueMember"].map((attr) => (
                                                <SelectOption
                                                    key={attr}
                                                    value={attr}
                                                />
                                                ))}
                                        </Select>
                                    </Col>
                                </FormGroup>
                                <FormGroup
                                    key="memberOfGroupAttr"
                                    controlId="memberOfGroupAttr"
                                    disabled={false}
                                >
                                    <Col
                                        componentClass={ControlLabel}
                                        sm={3}
                                        title="Specifies the attribute in the group entry to use to identify the DNs of group members (memberOfGroupAttr)"
                                    >
                                        Group Attribute
                                    </Col>
                                    <Col sm={8}>
                                        <Select
                                            variant={SelectVariant.typeaheadMulti}
                                            typeAheadAriaLabel="Type a member group attribute"
                                            onToggle={this.onMemberOfGroupAttrToggle}
                                            onSelect={this.onMemberOfGroupAttrSelect}
                                            onClear={this.onMemberOfGroupAttrClear}
                                            selections={memberOfGroupAttr}
                                            isOpen={this.state.isMemberOfGroupAttrOpen}
                                            aria-labelledby="typeAhead-memberof-group-attr"
                                            placeholderText="Type a member group attribute..."
                                            noResultsFoundText="There are no matching entries"
                                            isCreatable
                                            onCreateOption={this.onMemberOfGroupAttrCreateOption}
                                            >
                                            {attributeTypes.map((attr, index) => (
                                                <SelectOption
                                                    key={index}
                                                    value={attr}
                                                />
                                                ))}
                                        </Select>
                                    </Col>
                                </FormGroup>
                            </Form>
                        </Col>
                    </Row>
                    <Row>
                        <Col sm={12}>
                            <Form horizontal>
                                <FormGroup
                                    key="memberOfEntryScope"
                                    controlId="memberOfEntryScope"
                                    disabled={false}
                                >
                                    <Col
                                        componentClass={ControlLabel}
                                        sm={3}
                                        title="Specifies backends or multiple-nested suffixes for the MemberOf plug-in to work on (memberOfEntryScope)"
                                    >
                                        Entry Scope
                                    </Col>
                                    <Col sm={6}>
                                        <FormControl
                                            type="text"
                                            value={memberOfEntryScope}
                                            onChange={this.handleFieldChange}
                                        />
                                    </Col>
                                    <Col sm={3}>
                                        <Checkbox
                                            id="memberOfAllBackends"
                                            isChecked={memberOfAllBackends}
                                            onChange={this.handleCheckboxChange}
                                            title="Specifies whether to search the local suffix for user entries on all available suffixes (memberOfAllBackends)"
                                            label="All Backends"
                                        />
                                    </Col>
                                </FormGroup>
                                <FormGroup
                                    key="memberOfEntryScopeExcludeSubtree"
                                    controlId="memberOfEntryScopeExcludeSubtree"
                                    disabled={false}
                                >
                                    <Col
                                        componentClass={ControlLabel}
                                        sm={3}
                                        title="Specifies backends or multiple-nested suffixes for the MemberOf plug-in to exclude (memberOfEntryScopeExcludeSubtree)"
                                    >
                                        Entry Scope Exclude Subtree
                                    </Col>
                                    <Col sm={6}>
                                        <FormControl
                                            type="text"
                                            value={memberOfEntryScopeExcludeSubtree}
                                            onChange={this.handleFieldChange}
                                        />
                                    </Col>
                                    <Col sm={3}>
                                        <Checkbox
                                            id="memberOfSkipNested"
                                            isChecked={memberOfSkipNested}
                                            onChange={this.handleCheckboxChange}
                                            title="Specifies wherher to skip nested groups or not (memberOfSkipNested)"
                                            label="Skip Nested"
                                        />
                                    </Col>
                                </FormGroup>
                            </Form>
                        </Col>
                    </Row>
                    <Row>
                        <Col sm={12}>
                            <Form horizontal>
                                <FormGroup
                                    key="memberOfConfigEntry"
                                    controlId="memberOfConfigEntry"
                                >
                                    <Col
                                        componentClass={ControlLabel}
                                        sm={3}
                                        title="The value to set as nsslapd-pluginConfigArea"
                                    >
                                        Shared Config Entry
                                    </Col>
                                    <Col sm={6}>
                                        <FormControl
                                            type="text"
                                            value={memberOfConfigEntry}
                                            onChange={this.handleFieldChange}
                                        />
                                    </Col>
                                    <Col sm={3}>
                                        <Button variant="primary" onClick={this.openModal}>
                                            Manage
                                        </Button>
                                    </Col>
                                </FormGroup>
                            </Form>
                        </Col>
                    </Row>
                    <Row>
                        <Col sm={12}>
                            <Form horizontal>
                                <FormGroup controlId="memberOfAutoAddOC" disabled={false}>
                                    <Col
                                        componentClass={ControlLabel}
                                        sm={3}
                                        title="If an entry does not have an object class that allows the memberOf attribute then the memberOf plugin will automatically add the object class listed in the memberOfAutoAddOC parameter"
                                    >
                                        Auto Add OC
                                    </Col>
                                    <Col sm={8}>
                                        <Select
                                            variant={SelectVariant.typeahead}
                                            typeAheadAriaLabel="Type an objectClass"
                                            onToggle={this.onMemberOfAutoAddOCToggle}
                                            onSelect={this.onMemberOfAutoAddOCSelect}
                                            onClear={this.onMemberOfAutoAddOCClear}
                                            selections={memberOfAutoAddOC}
                                            isOpen={this.state.isMemberOfAutoAddOCOpen}
                                            aria-labelledby="typeAhead-memberof-auto-addoc"
                                            placeholderText="Type an objectClass..."
                                            noResultsFoundText="There are no matching entries"
                                            isCreatable
                                            onCreateOption={this.onMemberOfAutoAddOCCreateOption}
                                            >
                                            {objectClasses.map((attr, index) => (
                                                <SelectOption
                                                    key={index}
                                                    value={attr}
                                                />
                                                ))}
                                        </Select>
                                    </Col>
                                </FormGroup>
                            </Form>
                        </Col>
                    </Row>
                    <Row>
                        <Col sm={12}>
                            <Button variant="primary" onClick={this.toggleFixupModal}>
                                Run Fixup Task
                            </Button>
                        </Col>
                    </Row>
                </PluginBasicConfig>
            </div>
        );
    }
}

MemberOf.propTypes = {
    rows: PropTypes.array,
    serverId: PropTypes.string,
    savePluginHandler: PropTypes.func,
    pluginListHandler: PropTypes.func,
    addNotification: PropTypes.func,
    toggleLoadingHandler: PropTypes.func
};

MemberOf.defaultProps = {
    rows: [],
    serverId: "",
    savePluginHandler: noop,
    pluginListHandler: noop,
    addNotification: noop,
    toggleLoadingHandler: noop
};

export default MemberOf;
