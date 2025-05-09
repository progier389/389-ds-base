import React from "react";
import cockpit from "cockpit";
import {
	Button,
	Checkbox,
	Form,
	FormHelperText,
	FormSelect,
	FormSelectOption,
	Grid,
	GridItem,
	Modal,
	ModalVariant,
	NumberInput,
	Radio,
	Spinner,
	Tab,
	Tabs,
	TabTitleIcon,
	TabTitleText,
	TextInput,
	Text,
	TextContent,
	TextVariants,
	TimePicker,
	ValidatedOptions
} from '@patternfly/react-core';
import {
	Select,
	SelectVariant,
	SelectOption
} from '@patternfly/react-core/deprecated';
import PropTypes from "prop-types";
import { ExclamationTriangleIcon } from '@patternfly/react-icons/dist/js/icons/exclamation-triangle-icon';

const _ = cockpit.gettext;

export class WinsyncAgmtModal extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            activeTabKey: 0,
        };

        // Toggle currently active tab
        this.handleNavSelect = (event, tabIndex) => {
            event.preventDefault();
            this.setState({
                activeTabKey: tabIndex
            });
        };
    }

    hasMainErrors(errors) {
        const attrs = [
            'agmtName', 'agmtHost', 'agmtPort', 'agmtBindDN', 'agmtBindPW', 'agmtBindPWConfirm'
        ];
        for (const attr of attrs) {
            if (attr in errors && errors[attr]) {
                return true;
            }
        }
        return false;
    }

    hasDomainErrors(errors) {
        const attrs = [
            'agmtWinDomain', 'agmtWinSubtree', 'agmtDSSubtree',
        ];
        for (const attr of attrs) {
            if (attr in errors && errors[attr]) {
                return true;
            }
        }
        return false;
    }

    hasScheduleErrors(errors) {
        const attrs = [
            'agmtStartTime', 'agmtEndTime',
        ];
        for (const attr of attrs) {
            if (attr in errors && errors[attr]) {
                return true;
            }
        }
        return false;
    }

    render() {
        const {
            showModal,
            closeHandler,
            saveHandler,
            handleChange,
            handleTimeChange,
            handleFracChange,
            onSelectToggle,
            onSelectClear,
            spinning,
            agmtName,
            agmtHost,
            agmtPort,
            agmtProtocol,
            agmtBindDN,
            agmtBindPW,
            agmtBindPWConfirm,
            agmtFracAttrs,
            agmtSync,
            agmtSyncMon,
            agmtSyncTue,
            agmtSyncWed,
            agmtSyncThu,
            agmtSyncFri,
            agmtSyncSat,
            agmtSyncSun,
            agmtStartTime,
            agmtEndTime,
            agmtSyncGroups,
            agmtSyncUsers,
            agmtWinDomain,
            agmtWinSubtree,
            agmtDSSubtree,
            agmtOneWaySync, // "both", "toWindows", "fromWindows"
            agmtSyncInterval,
            agmtInit,
            availAttrs,
            error,
            isExcludeAttrOpen,
        } = this.props;
        const saveDisabled = !this.props.saveOK;
        let title = _("Create");
        let initRow = "";
        let name = "agmt-modal";
        const startHour = agmtStartTime.substring(0, 2);
        const startMin = agmtStartTime.substring(2, 4);
        const startTime = startHour + ":" + startMin;
        const endHour = agmtEndTime.substring(0, 2);
        const endMin = agmtEndTime.substring(2, 4);
        const endTime = endHour + ":" + endMin;
        let saveBtnName = _("Save Agreement");
        const extraPrimaryProps = {};
        if (spinning) {
            saveBtnName = _("Saving Agreement ...");
            extraPrimaryProps.spinnerAriaValueText = _("Saving");
        }
        let mainSettingsError = "";
        let scheduleError = "";
        let domainError = "";
        if (this.hasMainErrors(error)) {
            mainSettingsError = <TabTitleIcon className="ds-warning-icon"><ExclamationTriangleIcon /></TabTitleIcon>;
        }
        if (this.hasDomainErrors(error)) {
            domainError = <TabTitleIcon className="ds-warning-icon"><ExclamationTriangleIcon /></TabTitleIcon>;
        }
        if (this.hasScheduleErrors(error)) {
            scheduleError = <TabTitleIcon className="ds-warning-icon"><ExclamationTriangleIcon /></TabTitleIcon>;
        }

        if (this.props.edit) {
            title = _("Edit");
            name = "agmt-modal-edit";
        } else {
            initRow = (
                <Grid className="ds-margin-top">
                    <GridItem className="ds-label" span={3}>
                        {_("Consumer Initialization")}
                    </GridItem>
                    <GridItem span={9}>
                        <FormSelect
                            value={agmtInit}
                            id="agmtInit"
                            onChange={(e, str) => {
                                handleChange(e);
                            }}
                            aria-label="FormSelect Input"
                        >
                            <FormSelectOption key={0} value="noinit" label={_("Do Not Initialize")} />
                            <FormSelectOption key={1} value="online-init" label={_("Do Online Initialization")} />
                        </FormSelect>
                    </GridItem>
                </Grid>
            );
        }

        let scheduleRow = (
            <div className="ds-left-indent-md">
                <Grid className="ds-margin-top-lg">
                    <GridItem className="ds-label" span={12}>
                        {_("Days To Send Synchronization Updates")}
                    </GridItem>
                </Grid>
                <div className="ds-indent ds-margin-top">
                    <Grid>
                        <GridItem span={3}>
                            <Checkbox
                                id="agmtSyncMon"
                                onChange={(e, checked) => {
                                    handleChange(e);
                                }}
                                name={name}
                                isChecked={agmtSyncMon}
                                label={_("Monday")}
                                isValid={!error.agmtSyncMon}
                            />
                        </GridItem>
                        <GridItem span={3}>
                            <Checkbox
                                id="agmtSyncFri"
                                onChange={(e, checked) => {
                                    handleChange(e);
                                }}
                                name={name}
                                isChecked={agmtSyncFri}
                                label={_("Friday")}
                                isValid={!error.agmtSyncFri}
                            />
                        </GridItem>
                    </Grid>
                    <Grid className="ds-margin-top">
                        <GridItem span={3}>
                            <Checkbox
                                id="agmtSyncTue"
                                onChange={(e, checked) => {
                                    handleChange(e);
                                }}
                                name={name}
                                isChecked={agmtSyncTue}
                                isValid={!error.agmtSyncTue}
                                label={_("Tuesday")}
                            />
                        </GridItem>
                        <GridItem span={3}>
                            <Checkbox
                                id="agmtSyncSat"
                                onChange={(e, checked) => {
                                    handleChange(e);
                                }}
                                name={name}
                                isChecked={agmtSyncSat}
                                isValid={!error.agmtSyncSat}
                                label={_("Saturday")}
                            />
                        </GridItem>
                    </Grid>
                    <Grid className="ds-margin-top">
                        <GridItem span={3}>
                            <Checkbox
                                id="agmtSyncWed"
                                onChange={(e, checked) => {
                                    handleChange(e);
                                }}
                                name={name}
                                isChecked={agmtSyncWed}
                                label={_("Wednesday")}
                                isValid={!error.agmtSyncWed}
                            />
                        </GridItem>
                        <GridItem span={3}>
                            <Checkbox
                                id="agmtSyncSun"
                                onChange={(e, checked) => {
                                    handleChange(e);
                                }}
                                name={name}
                                isChecked={agmtSyncSun}
                                isValid={!error.agmtSyncSun}
                                label={_("Sunday")}
                            />
                        </GridItem>
                    </Grid>
                    <Grid className="ds-margin-top">
                        <GridItem span={3}>
                            <Checkbox
                                id="agmtSyncThu"
                                onChange={(e, checked) => {
                                    handleChange(e);
                                }}
                                name={name}
                                isChecked={agmtSyncThu}
                                isValid={!error.agmtSyncThu}
                                label={_("Thursday")}
                            />
                        </GridItem>
                    </Grid>
                </div>
                <Grid className="ds-margin-top-lg" title={_("Time to start initiating replication sessions")}>
                    <GridItem className="ds-label" span={3}>
                        {_("Replication Start Time")}
                    </GridItem>
                    <GridItem span={9}>
                        <TimePicker
                            time={startTime}
                            id="agmtStartTime"
                            onChange={(_event, time, hour, min, seconds, isValid) => {
                                handleTimeChange(this.props.edit ? "edit" : "create", "agmtStartTime", time);
                            }}
                            stepMinutes={5}
                            direction="up"
                            is24Hour
                        />
                        <FormHelperText  >
                            {_("Start time must be before the End time")}
                        </FormHelperText>
                    </GridItem>
                </Grid>
                <Grid title={_("Time to initiating replication sessions")}>
                    <GridItem className="ds-label" span={3}>
                        {_("Replication End Time")}
                    </GridItem>
                    <GridItem span={9}>
                        <TimePicker
                            time={endTime}
                            id="agmtEndTime"
                            onChange={(_event, time, hour, min, seconds, isValid) => {
                                handleTimeChange(this.props.edit ? "edit" : "create", "agmtEndTime", time);
                            }}
                            stepMinutes={5}
                            direction="up"
                            is24Hour
                        />
                        <FormHelperText  >
                            {_("End time must be after the Start time")}
                        </FormHelperText>
                    </GridItem>
                </Grid>
            </div>
        );

        if (!agmtSync) {
            scheduleRow = "";
        }

        title = cockpit.format(_("$0 Winsync Agreement"), title);

        return (
            <Modal
                variant={ModalVariant.medium}
                className="ds-modal-winsync-agmt"
                aria-labelledby="ds-modal"
                title={title}
                isOpen={showModal}
                onClose={closeHandler}
                actions={[
                    <Button
                        key="confirm"
                        variant="primary"
                        isDisabled={saveDisabled || spinning}
                        onClick={saveHandler}
                        isLoading={spinning}
                        spinnerAriaValueText={spinning ? _("Saving") : undefined}
                        {...extraPrimaryProps}
                    >
                        {saveBtnName}
                    </Button>,
                    <Button key="cancel" variant="link" onClick={closeHandler}>
                        {_("Cancel")}
                    </Button>
                ]}
            >
                <div className={spinning ? "ds-disabled" : ""}>
                    <Form isHorizontal autoComplete="off">
                        <Tabs activeKey={this.state.activeTabKey} onSelect={this.handleNavSelect}>
                            <Tab eventKey={0} title={<>{mainSettingsError}<TabTitleText>{_("Main Settings")}</TabTitleText></>}>
                                <Grid className="ds-margin-top">
                                    <GridItem className="ds-label" span={3}>
                                        {_("Agreement Name")}
                                    </GridItem>
                                    <GridItem span={9}>
                                        <TextInput
                                            value={agmtName}
                                            type="text"
                                            id="agmtName"
                                            aria-describedby="horizontal-form-name-helper"
                                            name="agmtName"
                                            onChange={(e, str) => {
                                                handleChange(e);
                                            }}
                                            isDisabled={this.props.edit}
                                            validated={error.agmtName ? ValidatedOptions.error : ValidatedOptions.default}
                                        />
                                    </GridItem>
                                </Grid>
                                <Grid className="ds-margin-top-lg">
                                    <GridItem className="ds-label" span={3}>
                                        {_("Windows AD Host")}
                                    </GridItem>
                                    <GridItem span={9}>
                                        <TextInput
                                            value={agmtHost}
                                            type="text"
                                            id="agmtHost"
                                            aria-describedby="horizontal-form-name-helper"
                                            name="agmtHost"
                                            onChange={(e, str) => {
                                                handleChange(e);
                                            }}
                                            validated={error.agmtHost ? ValidatedOptions.error : ValidatedOptions.default}
                                        />
                                    </GridItem>
                                </Grid>
                                <Grid className="ds-margin-top-lg">
                                    <GridItem className="ds-label" span={3}>
                                        {_("Windows AD Port")}
                                    </GridItem>
                                    <GridItem span={9}>
                                        <TextInput
                                            value={agmtPort}
                                            type="number"
                                            id="agmtPort"
                                            aria-describedby="horizontal-form-name-helper"
                                            name="agmtPort"
                                            onChange={(e, str) => {
                                                handleChange(e);
                                            }}
                                            validated={error.agmtPort ? ValidatedOptions.error : ValidatedOptions.default}
                                        />
                                    </GridItem>
                                </Grid>
                                <Grid className="ds-margin-top-lg">
                                    <GridItem className="ds-label" span={3}>
                                        {_("Bind DN")}
                                    </GridItem>
                                    <GridItem span={9}>
                                        <TextInput
                                            value={agmtBindDN}
                                            type="text"
                                            id="agmtBindDN"
                                            aria-describedby="horizontal-form-name-helper"
                                            name="agmtBindDN"
                                            onChange={(e, str) => {
                                                handleChange(e);
                                            }}
                                            validated={error.agmtBindDN ? ValidatedOptions.error : ValidatedOptions.default}
                                        />
                                        <FormHelperText  >
                                            {_("Value must be a valid DN")}
                                        </FormHelperText>
                                    </GridItem>
                                </Grid>
                                <Grid className="ds-margin-top">
                                    <GridItem className="ds-label" span={3}>
                                        {_("Bind Password")}
                                    </GridItem>
                                    <GridItem span={9}>
                                        <TextInput
                                            value={agmtBindPW}
                                            type="password"
                                            id="agmtBindPW"
                                            aria-describedby="horizontal-form-name-helper"
                                            name="agmtBindPW"
                                            onChange={(e, str) => {
                                                handleChange(e);
                                            }}
                                            validated={error.agmtBindPW ? ValidatedOptions.error : ValidatedOptions.default}
                                        />
                                        <FormHelperText  >
                                            {_("Passwords must match")}
                                        </FormHelperText>
                                    </GridItem>
                                </Grid>
                                <Grid className="ds-margin-top">
                                    <GridItem className="ds-label" span={3}>
                                        {_("Confirm Password")}
                                    </GridItem>
                                    <GridItem span={9}>
                                        <TextInput
                                            value={agmtBindPWConfirm}
                                            type="password"
                                            id="agmtBindPWConfirm"
                                            aria-describedby="horizontal-form-name-helper"
                                            name="agmtBindPWConfirm"
                                            onChange={(e, str) => {
                                                handleChange(e);
                                            }}
                                            validated={error.agmtBindPWConfirm ? ValidatedOptions.error : ValidatedOptions.default}
                                        />
                                        <FormHelperText  >
                                            {_("Passwords must match")}
                                        </FormHelperText>
                                    </GridItem>
                                </Grid>
                                {initRow}
                            </Tab>
                            <Tab eventKey={1} title={<>{domainError}<TabTitleText>{_("Domain & Content")}</TabTitleText></>}>
                                <Grid className="ds-margin-top">
                                    <GridItem className="ds-label" span={3}>
                                        {_("Windows Domain Name")}
                                    </GridItem>
                                    <GridItem span={9}>
                                        <TextInput
                                            value={agmtWinDomain}
                                            type="text"
                                            id="agmtWinDomain"
                                            aria-describedby="horizontal-form-name-helper"
                                            name="agmtWinDomain"
                                            onChange={(e, str) => {
                                                handleChange(e);
                                            }}
                                            validated={error.agmtWinDomain ? ValidatedOptions.error : ValidatedOptions.default}
                                        />
                                    </GridItem>
                                </Grid>
                                <Grid className="ds-margin-top-lg" title={_("The Active Directory subtree to synchronize")}>
                                    <GridItem className="ds-label" span={3}>
                                        {_("Windows Subtree")}
                                    </GridItem>
                                    <GridItem span={9}>
                                        <TextInput
                                            value={agmtWinSubtree}
                                            type="text"
                                            id="agmtWinSubtree"
                                            aria-describedby="horizontal-form-name-helper"
                                            name="agmtWinSubtree"
                                            onChange={(e, str) => {
                                                handleChange(e);
                                            }}
                                            placeholder={_("e.g. cn=Users,dc=domain,dc=com")}
                                            validated={error.agmtWinSubtree ? ValidatedOptions.error : ValidatedOptions.default}
                                        />
                                        <FormHelperText  >
                                            Value must be a valid DN
                                        </FormHelperText>
                                    </GridItem>
                                </Grid>
                                <Grid className="ds-margin-top" title={_("Directory Server subtree to synchronize")}>
                                    <GridItem className="ds-label" span={3}>
                                        {_("DS Subtree")}
                                    </GridItem>
                                    <GridItem span={9}>
                                        <TextInput
                                            value={agmtDSSubtree}
                                            type="text"
                                            id="agmtDSSubtree"
                                            aria-describedby="horizontal-form-name-helper"
                                            name="agmtDSSubtree"
                                            onChange={(e, str) => {
                                                handleChange(e);
                                            }}
                                            placeholder={_("e.g. ou=People,dc=domain,dc=com")}
                                            validated={error.agmtDSSubtree ? ValidatedOptions.error : ValidatedOptions.default}
                                        />
                                        <FormHelperText  >
                                            {_("Value must be a valid DN")}
                                        </FormHelperText>
                                    </GridItem>
                                </Grid>
                            </Tab>
                            <Tab eventKey={2} title={<TabTitleText>{_("Advanced Settings")}</TabTitleText>}>
                                <Grid className="ds-margin-top">
                                    <GridItem className="ds-label" span={3}>
                                        {_("Connection Protocol")}
                                    </GridItem>
                                    <GridItem span={9}>
                                        <FormSelect
                                            value={agmtProtocol}
                                            id="agmtProtocol"
                                            onChange={(e, str) => {
                                                handleChange(e);
                                            }}
                                            aria-label="FormSelect Input"
                                        >
                                            <FormSelectOption key={0} value="LDAPS" label={_("LDAPS")} />
                                            <FormSelectOption key={1} value="StartTLS" label={_("StartTLS")} />
                                        </FormSelect>
                                    </GridItem>
                                </Grid>
                                <Grid className="ds-margin-top">
                                    <GridItem className="ds-label" span={3}>
                                        {_("Synchronization Direction")}
                                    </GridItem>
                                    <GridItem span={9}>
                                        <FormSelect
                                            value={agmtOneWaySync}
                                            id="agmtOneWaySync"
                                            onChange={(e, str) => {
                                                handleChange(e);
                                            }}
                                            aria-label="FormSelect Input"
                                        >
                                            <FormSelectOption title={_("Synchronization in both directions (default behavior).")} key={0} value="both" label={_("both")} />
                                            <FormSelectOption title={_("Only synchronize Directory Server updates to Windows.")} key={1} value="toWindows" label={_("toWindows")} />
                                            <FormSelectOption title={_("Only synchronize Windows updates to Directory Server.")} key={2} value="fromWindows" label={_("fromWindows")} />
                                        </FormSelect>
                                    </GridItem>
                                </Grid>
                                <Grid className="ds-margin-top" title={_("The interval to check for updates on Windows.  Default is 300 seconds")}>
                                    <GridItem className="ds-label" span={3}>
                                        {_("Synchronization Interval")}
                                    </GridItem>
                                    <GridItem span={9}>
                                        <TextInput
                                            value={agmtSyncInterval}
                                            type="number"
                                            id="agmtSyncInterval"
                                            aria-describedby="horizontal-form-name-helper"
                                            name="agmtSyncInterval"
                                            onChange={(e, str) => {
                                                handleChange(e);
                                            }}
                                            validated={error.agmtSyncInterval ? ValidatedOptions.error : ValidatedOptions.default}
                                        />
                                    </GridItem>
                                </Grid>
                                <Grid className="ds-margin-top" title={_("Attribute to exclude from replication")}>
                                    <GridItem className="ds-label" span={3}>
                                        {_("Exclude Attributes")}
                                    </GridItem>
                                    <GridItem span={9}>
                                        <Select
                                            variant={SelectVariant.typeaheadMulti}
                                            typeAheadAriaLabel="Type an attribute"
                                            onToggle={onSelectToggle}
                                            onSelect={(e, selection) => { handleFracChange(selection) }}
                                            onClear={onSelectClear}
                                            selections={agmtFracAttrs}
                                            isOpen={isExcludeAttrOpen}
                                            aria-labelledby="typeAhead-exclude-attrs"
                                            placeholderText={_("Start typing an attribute...")}
                                            noResultsFoundText={_("There are no matching entries")}
                                        >
                                            {availAttrs.map((attr, index) => (
                                                <SelectOption
                                                    key={index}
                                                    value={attr}
                                                />
                                            ))}
                                        </Select>
                                    </GridItem>
                                </Grid>
                                <Grid className="ds-margin-top-med">
                                    <GridItem>
                                        <Checkbox
                                            id="agmtSyncGroups"
                                            onChange={(e, checked) => {
                                                handleChange(e);
                                            }}
                                            name={name}
                                            isChecked={agmtSyncGroups}
                                            label={_("Synchronize New Windows Groups")}
                                        />
                                    </GridItem>
                                </Grid>
                                <Grid className="ds-margin-top">
                                    <GridItem>
                                        <Checkbox
                                            id="agmtSyncUsers"
                                            onChange={(e, checked) => {
                                                handleChange(e);
                                            }}
                                            name={name}
                                            isChecked={agmtSyncUsers}
                                            label={_("Synchronize New Windows Users")}
                                        />
                                    </GridItem>
                                </Grid>

                            </Tab>
                            <Tab eventKey={3} title={<>{scheduleError}<TabTitleText>{_("Scheduling")}</TabTitleText></>}>
                                <Grid className="ds-margin-top">
                                    <GridItem span={12}>
                                        <TextContent>
                                            <Text component={TextVariants.h5}>
                                                {_("By default replication updates are sent to the replica as soon as possible, but if there is a need for replication updates to only be sent on certain days and within certain windows of time then you can setup a custom replication schedule.")}
                                            </Text>
                                        </TextContent>
                                    </GridItem>
                                    <GridItem className="ds-margin-top-lg" span={12}>
                                        <Checkbox
                                            id="agmtSync"
                                            isChecked={agmtSync}
                                            onChange={(e, checked) => {
                                                handleChange(e);
                                            }}
                                            name={name}
                                            label={_("Use A Custom Schedule")}
                                        />
                                    </GridItem>
                                </Grid>
                                {scheduleRow}
                            </Tab>
                        </Tabs>
                    </Form>
                </div>
            </Modal>
        );
    }
}

export class ReplAgmtModal extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            activeTabKey: 0,
        };

        // Toggle currently active tab
        this.handleNavSelect = (event, tabIndex) => {
            event.preventDefault();
            this.setState({
                activeTabKey: tabIndex
            });
        };
    }

    hasMainErrors(errors) {
        const attrs = [
            'agmtName', 'agmtHost', 'agmtPort', 'agmtBindDN', 'agmtBindPW', 'agmtBindPWConfirm'
        ];
        for (const attr of attrs) {
            if (attr in errors && errors[attr]) {
                return true;
            }
        }
        return false;
    }

    hasBootErrors(errors) {
        const attrs = [
            'agmtBootstrapBindDN', 'agmtBootstrapBindPW', 'agmtBootstrapBindPWConfirm'
        ];
        for (const attr of attrs) {
            if (attr in errors && errors[attr]) {
                return true;
            }
        }
        return false;
    }

    hasScheduleErrors(errors) {
        const attrs = [
            'agmtStartTime', 'agmtEndTime'
        ];
        for (const attr of attrs) {
            if (attr in errors && errors[attr]) {
                return true;
            }
        }
        return false;
    }

    render() {
        const {
            showModal,
            closeHandler,
            saveHandler,
            handleChange,
            handleTimeChange,
            handleStripChange,
            handleFracChange,
            handleFracInitChange,
            onExcludeAttrsToggle,
            onExcludeAttrsClear,
            onExcludeAttrsInitToggle,
            onExcludeAttrsInitClear,
            onStripAttrsToggle,
            onStripAttrsClear,
            isExcludeAttrsOpen,
            isExcludeInitAttrsOpen,
            isStripAttrsOpen,
            spinning,
            agmtName,
            agmtHost,
            agmtPort,
            agmtProtocol,
            agmtBindMethod,
            agmtBindMethodOptions,
            agmtBindDN,
            agmtBindPW,
            agmtBindPWConfirm,
            agmtBootstrap,
            agmtBootstrapBindDN,
            agmtBootstrapBindPW,
            agmtBootstrapBindPWConfirm,
            agmtBootstrapProtocol,
            agmtBootstrapBindMethod,
            agmtBootstrapBindMethodOptions,
            agmtStripAttrs,
            agmtFracAttrs,
            agmtFracInitAttrs,
            agmtSync,
            agmtSyncMon,
            agmtSyncTue,
            agmtSyncWed,
            agmtSyncThu,
            agmtSyncFri,
            agmtSyncSat,
            agmtSyncSun,
            agmtStartTime,
            agmtEndTime,
            agmtInit,
            availAttrs,
            error,
        } = this.props;
        const saveDisabled = !this.props.saveOK;
        let title = _("Create");
        let initRow = "";
        let name = "agmt-modal";
        const bootstrapTitle = _("If you are using Bind Group's on the consumer replica you can configure bootstrap credentials that can be used to do online initializations, or bootstrap a session if the bind groups get out of synchronization");
        const startHour = agmtStartTime.substring(0, 2);
        const startMin = agmtStartTime.substring(2, 4);
        const startTime = startHour + ":" + startMin;
        const endHour = agmtEndTime.substring(0, 2);
        const endMin = agmtEndTime.substring(2, 4);
        const endTime = endHour + ":" + endMin;
        let saveBtnName = _("Save Agreement");
        const extraPrimaryProps = {};
        if (spinning) {
            saveBtnName = _("Saving Agreement ...");
            extraPrimaryProps.spinnerAriaValueText = _("Saving");
        }

        let mainSettingsError = "";
        let bootSettingsError = "";
        let scheduleSettingsError = "";
        if (this.hasMainErrors(error)) {
            mainSettingsError = <TabTitleIcon className="ds-warning-icon"><ExclamationTriangleIcon /></TabTitleIcon>;
        }
        if (this.hasBootErrors(error)) {
            bootSettingsError = <TabTitleIcon className="ds-warning-icon"><ExclamationTriangleIcon /></TabTitleIcon>;
        }
        if (this.hasScheduleErrors(error)) {
            scheduleSettingsError = <TabTitleIcon className="ds-warning-icon"><ExclamationTriangleIcon /></TabTitleIcon>;
        }

        if (this.props.edit) {
            title = _("Edit");
            name = "agmt-modal-edit";
        } else {
            initRow = (
                <Grid className="ds-margin-top-lg">
                    <GridItem className="ds-label" span={3}>
                        {_("Consumer Initialization")}
                    </GridItem>
                    <GridItem span={9}>
                        <FormSelect
                            value={agmtInit}
                            id="agmtInit"
                            onChange={(e, str) => {
                                handleChange(e);
                            }}
                            aria-label="FormSelect Input"
                        >
                            <FormSelectOption key={0} value="noinit" label={_("Do Not Initialize")} />
                            <FormSelectOption key={1} value="online-init" label={_("Do Online Initialization")} />
                        </FormSelect>
                    </GridItem>
                </Grid>
            );
        }

        let bootstrapRow = (
            <div className="ds-left-indent-md">
                <Grid className="ds-margin-top-lg" title={_("The Bind DN the agreement can use to bootstrap initialization")}>
                    <GridItem className="ds-label" span={3}>
                        {_("Bind DN")}
                    </GridItem>
                    <GridItem span={9}>
                        <TextInput
                            value={agmtBootstrapBindDN}
                            type="text"
                            id="agmtBootstrapBindDN"
                            aria-describedby="horizontal-form-name-helper"
                            name="agmtBootstrapBindDN"
                            onChange={(e, str) => {
                                handleChange(e);
                            }}
                            validated={error.agmtBootstrapBindDN ? ValidatedOptions.error : ValidatedOptions.default}
                        />
                        <FormHelperText  >
                            {_("Value must be a valid DN")}
                        </FormHelperText>
                    </GridItem>
                </Grid>
                <Grid className="ds-margin-top">
                    <GridItem className="ds-label" span={3} title={_("The Bind DN password for bootstrap initialization")}>
                        {_("Password")}
                    </GridItem>
                    <GridItem span={9}>
                        <TextInput
                            value={agmtBootstrapBindPW}
                            type="password"
                            id="agmtBootstrapBindPW"
                            aria-describedby="horizontal-form-name-helper"
                            name="agmtBootstrapBindPW"
                            onChange={(e, str) => {
                                handleChange(e);
                            }}
                            validated={error.agmtBootstrapBindPW ? ValidatedOptions.error : ValidatedOptions.default}
                        />
                        <FormHelperText  >
                            {_("Password must match")}
                        </FormHelperText>
                    </GridItem>
                </Grid>
                <Grid className="ds-margin-top">
                    <GridItem className="ds-label" span={3} title={_("Confirm the Bind DN password for bootstrap initialization")}>
                        {_("Confirm Password")}
                    </GridItem>
                    <GridItem span={9}>
                        <TextInput
                            value={agmtBootstrapBindPWConfirm}
                            type="password"
                            id="agmtBootstrapBindPWConfirm"
                            aria-describedby="horizontal-form-name-helper"
                            name="agmtBootstrapBindPWConfirm"
                            onChange={(e, str) => {
                                handleChange(e);
                            }}
                            validated={error.agmtBootstrapBindPWConfirm ? ValidatedOptions.error : ValidatedOptions.default}
                        />
                        <FormHelperText  >
                            {_("Passwords must match")}
                        </FormHelperText>
                    </GridItem>
                </Grid>
                <Grid className="ds-margin-top">
                    <GridItem className="ds-label" span={3} title={_("The connection protocol for bootstrap initialization")}>
                        {_("Connection Protocol")}
                    </GridItem>
                    <GridItem span={9}>
                        <FormSelect
                            value={agmtBootstrapProtocol}
                            id="agmtBootstrapProtocol"
                            onChange={(e, str) => {
                                handleChange(e);
                            }}
                            aria-label="FormSelect Input"
                            validated={error.agmtBootstrapProtocol ? ValidatedOptions.error : ValidatedOptions.default}
                        >
                            <FormSelectOption key={0} value="LDAP" label={_("LDAP")} />
                            <FormSelectOption key={1} value="LDAPS" label={_("LDAPS")} />
                            <FormSelectOption key={2} value="STARTTLS" label={_("STARTTLS")} />
                        </FormSelect>
                    </GridItem>
                </Grid>
                <Grid className="ds-margin-top-lg">
                    <GridItem className="ds-label" span={3} title={_("The authentication method for bootstrap initialization")}>
                        {_("Authentication Method")}
                    </GridItem>
                    <GridItem span={9}>
                        <FormSelect
                            value={agmtBootstrapBindMethod}
                            id="agmtBootstrapBindMethod"
                            onChange={(e, str) => {
                                handleChange(e);
                            }}
                            aria-label="FormSelect Input"
                            validated={error.agmtBootstrapBindMethod ? ValidatedOptions.error : ValidatedOptions.default}
                        >
                            {agmtBootstrapBindMethodOptions.map((option, index) => (
                                <FormSelectOption key={index} value={option} label={option} />
                            ))}
                        </FormSelect>
                    </GridItem>
                </Grid>
            </div>
        );

        let scheduleRow = (
            <div className="ds-left-indent-md">
                <Grid className="ds-margin-top-lg">
                    <GridItem className="ds-label" span={12}>
                        {_("Days To Send Replication Updates")}
                    </GridItem>
                </Grid>
                <div className="ds-indent ds-margin-top">
                    <Grid>
                        <GridItem span={3}>
                            <Checkbox
                                id="agmtSyncMon"
                                onChange={(e, checked) => {
                                    handleChange(e);
                                }}
                                name={name}
                                isChecked={agmtSyncMon}
                                label={_("Monday")}
                                isValid={!error.agmtSyncMon}
                            />
                        </GridItem>
                        <GridItem span={3}>
                            <Checkbox
                                id="agmtSyncFri"
                                onChange={(e, checked) => {
                                    handleChange(e);
                                }}
                                name={name}
                                isChecked={agmtSyncFri}
                                label={_("Friday")}
                                isValid={!error.agmtSyncFri}
                            />
                        </GridItem>
                    </Grid>
                    <Grid className="ds-margin-top">
                        <GridItem span={3}>
                            <Checkbox
                                id="agmtSyncTue"
                                onChange={(e, checked) => {
                                    handleChange(e);
                                }}
                                name={name}
                                isChecked={agmtSyncTue}
                                isValid={!error.agmtSyncTue}
                                label={_("Tuesday")}
                            />
                        </GridItem>
                        <GridItem span={3}>
                            <Checkbox
                                id="agmtSyncSat"
                                onChange={(e, checked) => {
                                    handleChange(e);
                                }}
                                name={name}
                                isChecked={agmtSyncSat}
                                isValid={!error.agmtSyncSat}
                                label={_("Saturday")}
                            />
                        </GridItem>
                    </Grid>
                    <Grid className="ds-margin-top">
                        <GridItem span={3}>
                            <Checkbox
                                id="agmtSyncWed"
                                onChange={(e, checked) => {
                                    handleChange(e);
                                }}
                                name={name}
                                isChecked={agmtSyncWed}
                                label={_("Wednesday")}
                                isValid={!error.agmtSyncWed}
                            />
                        </GridItem>
                        <GridItem span={3}>
                            <Checkbox
                                id="agmtSyncSun"
                                onChange={(e, checked) => {
                                    handleChange(e);
                                }}
                                name={name}
                                isChecked={agmtSyncSun}
                                isValid={!error.agmtSyncSun}
                                label={_("Sunday")}
                            />
                        </GridItem>
                    </Grid>
                    <Grid className="ds-margin-top">
                        <GridItem span={3}>
                            <Checkbox
                                id="agmtSyncThu"
                                onChange={(e, checked) => {
                                    handleChange(e);
                                }}
                                name={name}
                                isChecked={agmtSyncThu}
                                isValid={!error.agmtSyncThu}
                                label={_("Thursday")}
                            />
                        </GridItem>
                    </Grid>
                </div>
                <Grid className="ds-margin-top-lg" title={_("Time to start initiating replication sessions")}>
                    <GridItem className="ds-label" span={3}>
                        {_("Replication Start Time")}
                    </GridItem>
                    <GridItem span={9}>
                        <TimePicker
                            time={startTime}
                            id="agmtStartTime"
                            onChange={(_event, time, hour, min, seconds, isValid) => {
                                handleTimeChange(this.props.edit ? "edit" : "create", "agmtStartTime", time);
                            }}
                            stepMinutes={5}
                            is24Hour
                        />
                        <FormHelperText  >
                            {_("Start time must be before the End time")}
                        </FormHelperText>
                    </GridItem>
                </Grid>
                <Grid title={_("Time to initiating replication sessions")}>
                    <GridItem className="ds-label" span={3}>
                        {_("Replication End Time")}
                    </GridItem>
                    <GridItem span={9}>
                        <TimePicker
                            time={endTime}
                            id="agmtEndTime"
                            onChange={(_event, time, hour, min, seconds, isValid) => {
                                handleTimeChange(this.props.edit ? "edit" : "create", "agmtEndTime", time);
                            }}
                            stepMinutes={5}
                            is24Hour
                        />
                        <FormHelperText  >
                            {_("End time must be after the Start time")}
                        </FormHelperText>
                    </GridItem>
                </Grid>
            </div>
        );

        if (!agmtSync) {
            scheduleRow = "";
        }
        if (!agmtBootstrap) {
            bootstrapRow = "";
        }

        title = cockpit.format(_("$0 Replication Agreement"), title);
        return (
            <Modal
                variant={ModalVariant.medium}
                title={title}
                className="ds-modal-repl-agmt"
                aria-labelledby="ds-modal"
                isOpen={showModal}
                onClose={closeHandler}
                actions={[
                    <Button
                        key="confirm"
                        variant="primary"
                        isDisabled={saveDisabled || spinning}
                        onClick={saveHandler}
                        isLoading={spinning}
                        spinnerAriaValueText={spinning ? _("Saving") : undefined}
                        {...extraPrimaryProps}
                    >
                        {saveBtnName}
                    </Button>,
                    <Button key="cancel" variant="link" onClick={closeHandler}>
                        {_("Cancel")}
                    </Button>
                ]}
            >
                <div className={spinning ? "ds-disabled" : ""}>
                    <Form isHorizontal autoComplete="off">
                        <Tabs activeKey={this.state.activeTabKey} onSelect={this.handleNavSelect}>
                            <Tab eventKey={0} title={<>{mainSettingsError}<TabTitleText>{_("Main Settings")}</TabTitleText></>}>
                                <Grid className="ds-margin-top">
                                    <GridItem className="ds-label" span={3}>
                                        {_("Agreement Name")}
                                    </GridItem>
                                    <GridItem span={9}>
                                        <TextInput
                                            value={agmtName}
                                            type="text"
                                            id="agmtName"
                                            aria-describedby="horizontal-form-name-helper"
                                            name="agmtName"
                                            onChange={(e, str) => {
                                                handleChange(e);
                                            }}
                                            isDisabled={this.props.edit}
                                            validated={error.agmtName ? ValidatedOptions.error : ValidatedOptions.default}
                                        />
                                        <FormHelperText  >
                                            {_("Required field")}
                                        </FormHelperText>
                                    </GridItem>
                                </Grid>
                                <Grid className="ds-margin-top">
                                    <GridItem className="ds-label" span={3}>
                                        {_("Consumer Host")}
                                    </GridItem>
                                    <GridItem span={9}>
                                        <TextInput
                                            value={agmtHost}
                                            type="text"
                                            id="agmtHost"
                                            aria-describedby="horizontal-form-name-helper"
                                            name="agmtHost"
                                            onChange={(e, str) => {
                                                handleChange(e);
                                            }}
                                            validated={error.agmtHost ? ValidatedOptions.error : ValidatedOptions.default}
                                        />
                                        <FormHelperText  >
                                            {_("Required field")}
                                        </FormHelperText>
                                    </GridItem>
                                </Grid>
                                <Grid className="ds-margin-top">
                                    <GridItem className="ds-label" span={3}>
                                        {_("Consumer Port")}
                                    </GridItem>
                                    <GridItem span={9}>
                                        <TextInput
                                            value={agmtPort}
                                            type="number"
                                            id="agmtPort"
                                            aria-describedby="horizontal-form-name-helper"
                                            name="agmtPort"
                                            onChange={(e, str) => {
                                                handleChange(e);
                                            }}
                                            validated={error.agmtPort ? ValidatedOptions.error : ValidatedOptions.default}
                                        />
                                        <FormHelperText  >
                                            {_("Port must be between 1 and 65535")}
                                        </FormHelperText>
                                    </GridItem>
                                </Grid>
                                <Grid className="ds-margin-top">
                                    <GridItem className="ds-label" span={3}>
                                        {_("Bind DN")}
                                    </GridItem>
                                    <GridItem span={9}>
                                        <TextInput
                                            value={agmtBindDN}
                                            type="text"
                                            id="agmtBindDN"
                                            aria-describedby="horizontal-form-name-helper"
                                            name="agmtBindDN"
                                            onChange={(e, str) => {
                                                handleChange(e);
                                            }}
                                            validated={error.agmtBindDN ? ValidatedOptions.error : ValidatedOptions.default}
                                        />
                                        <FormHelperText  >
                                            {_("Value must be a valid DN")}
                                        </FormHelperText>
                                    </GridItem>
                                </Grid>
                                <Grid className="ds-margin-top">
                                    <GridItem className="ds-label" span={3}>
                                        {_("Bind Password")}
                                    </GridItem>
                                    <GridItem span={9}>
                                        <TextInput
                                            value={agmtBindPW}
                                            type="password"
                                            id="agmtBindPW"
                                            aria-describedby="horizontal-form-name-helper"
                                            name="agmtBindPW"
                                            onChange={(e, str) => {
                                                handleChange(e);
                                            }}
                                            validated={error.agmtBindPW ? ValidatedOptions.error : ValidatedOptions.default}
                                        />
                                        <FormHelperText  >
                                            {_("Passwords must match")}
                                        </FormHelperText>
                                    </GridItem>
                                </Grid>
                                <Grid className="ds-margin-top">
                                    <GridItem className="ds-label" span={3}>
                                        {_("Confirm Password")}
                                    </GridItem>
                                    <GridItem span={9}>
                                        <TextInput
                                            value={agmtBindPWConfirm}
                                            type="password"
                                            id="agmtBindPWConfirm"
                                            aria-describedby="horizontal-form-name-helper"
                                            name="agmtBindPWConfirm"
                                            onChange={(e, str) => {
                                                handleChange(e);
                                            }}
                                            validated={error.agmtBindPWConfirm ? ValidatedOptions.error : ValidatedOptions.default}
                                        />
                                        <FormHelperText  >
                                            {_("Passwords must match")}
                                        </FormHelperText>
                                    </GridItem>
                                </Grid>
                                <Grid className="ds-margin-top">
                                    <GridItem className="ds-label" span={3}>
                                        {_("Connection Protocol")}
                                    </GridItem>
                                    <GridItem span={9}>
                                        <FormSelect
                                            value={agmtProtocol}
                                            id="agmtProtocol"
                                            onChange={(e, str) => {
                                                handleChange(e);
                                            }}
                                            aria-label="FormSelect Input"
                                            validated={error.agmtProtocol ? ValidatedOptions.error : ValidatedOptions.default}
                                        >
                                            <FormSelectOption key={0} value="LDAP" label={_("LDAP")} />
                                            <FormSelectOption key={1} value="LDAPS" label={_("LDAPS")} />
                                            <FormSelectOption key={2} value="STARTTLS" label={_("STARTTLS")} />
                                        </FormSelect>
                                    </GridItem>
                                </Grid>
                                <Grid className="ds-margin-top-lg">
                                    <GridItem className="ds-label" span={3}>
                                        {_("Authentication Method")}
                                    </GridItem>
                                    <GridItem span={9}>
                                        <FormSelect
                                            value={agmtBindMethod}
                                            id="agmtBindMethod"
                                            onChange={(e, str) => {
                                                handleChange(e);
                                            }}
                                            aria-label="FormSelect Input"
                                            validated={error.agmtBindMethod ? ValidatedOptions.error : ValidatedOptions.default}
                                        >
                                            {agmtBindMethodOptions.map((option, index) => (
                                                <FormSelectOption key={index} value={option} label={option} />
                                            ))}
                                        </FormSelect>
                                    </GridItem>
                                </Grid>
                                {initRow}
                            </Tab>
                            <Tab eventKey={1} title={<TabTitleText>{_("Fractional Settings")}</TabTitleText>}>
                                <Grid className="ds-margin-top-lg" title={_("Attribute to exclude from replication")}>
                                    <GridItem className="ds-label" span={3}>
                                        {_("Exclude Attributes")}
                                    </GridItem>
                                    <GridItem span={9}>
                                        <Select
                                            variant={SelectVariant.typeaheadMulti}
                                            typeAheadAriaLabel="Type an attribute"
                                            onToggle={onExcludeAttrsToggle}
                                            onSelect={(e, selection) => { handleFracChange(selection) }}
                                            onClear={onExcludeAttrsClear}
                                            selections={agmtFracAttrs}
                                            isOpen={isExcludeAttrsOpen}
                                            aria-labelledby="typeAhead-exclude-attrs"
                                            placeholderText={_("Start typing an attribute...")}
                                        >
                                            {availAttrs.map((attr, index) => (
                                                <SelectOption
                                                    key={index}
                                                    value={attr}
                                                />
                                            ))}
                                        </Select>
                                    </GridItem>
                                </Grid>
                                <Grid className="ds-margin-top" title={_("Attribute to exclude from replica Initializations")}>
                                    <GridItem className="ds-label" span={3}>
                                        {_("Exclude Init Attributes")}
                                    </GridItem>
                                    <GridItem span={9}>
                                        <Select
                                            variant={SelectVariant.typeaheadMulti}
                                            typeAheadAriaLabel="Type an attribute"
                                            onToggle={onExcludeAttrsInitToggle}
                                            onSelect={(e, selection) => { handleFracInitChange(selection) }}
                                            onClear={onExcludeAttrsInitClear}
                                            selections={agmtFracInitAttrs}
                                            isOpen={isExcludeInitAttrsOpen}
                                            aria-labelledby="typeAhead-exclude-init-attrs"
                                            placeholderText={_("Start typing an attribute...")}
                                            noResultsFoundText={_("There are no matching entries")}
                                        >
                                            {availAttrs.map((attr, index) => (
                                                <SelectOption
                                                    key={index}
                                                    value={attr}
                                                />
                                            ))}
                                        </Select>
                                    </GridItem>
                                </Grid>
                                <Grid className="ds-margin-top" title={_("Attributes to strip from a replication update")}>
                                    <GridItem className="ds-label" span={3}>
                                        {_("Strip Attributes")}
                                    </GridItem>
                                    <GridItem span={9}>
                                        <Select
                                            variant={SelectVariant.typeaheadMulti}
                                            typeAheadAriaLabel="Type an attribute"
                                            onToggle={onStripAttrsToggle}
                                            onSelect={(e, selection) => { handleStripChange(selection) }}
                                            onClear={onStripAttrsClear}
                                            selections={agmtStripAttrs}
                                            isOpen={isStripAttrsOpen}
                                            aria-labelledby="typeAhead-strip-attrs"
                                            placeholderText={_("Start typing an attribute...")}
                                            noResultsFoundText={_("There are no matching entries")}
                                        >
                                            {availAttrs.map((attr, index) => (
                                                <SelectOption
                                                    key={index}
                                                    value={attr}
                                                />
                                            ))}
                                        </Select>
                                    </GridItem>
                                </Grid>
                            </Tab>
                            <Tab eventKey={2} title={<>{bootSettingsError}<TabTitleText>{_("Bootstrap Settings")}</TabTitleText></>}>
                                <Grid className="ds-margin-top-med">
                                    <GridItem span={9}>
                                        <Checkbox
                                            id="agmtBootstrap"
                                            isChecked={agmtBootstrap}
                                            onChange={(e, checked) => {
                                                handleChange(e);
                                            }}
                                            name={name}
                                            title={bootstrapTitle}
                                            label={_("Enable Bootstrap Settings")}
                                        />
                                    </GridItem>
                                </Grid>
                                {bootstrapRow}
                            </Tab>
                            <Tab eventKey={3} title={<>{scheduleSettingsError}<TabTitleText>{_("Scheduling")}</TabTitleText></>}>
                                <Grid className="ds-margin-top-med">
                                    <GridItem span={12}>
                                        <TextContent>
                                            <Text component={TextVariants.h5}>
                                                {_("By default replication updates are sent to the replica as soon as possible, but if there is a need for replication updates to only be sent on certain days and within certain windows of time then you can setup a custom replication schedule.")}
                                            </Text>
                                        </TextContent>
                                    </GridItem>
                                    <GridItem className="ds-margin-top-lg" span={12}>
                                        <Checkbox
                                            id="agmtSync"
                                            isChecked={agmtSync}
                                            onChange={(e, checked) => {
                                                handleChange(e);
                                            }}
                                            name={name}
                                            label={_("Use A Custom Schedule")}
                                        />
                                    </GridItem>
                                </Grid>
                                {scheduleRow}
                            </Tab>
                        </Tabs>
                    </Form>
                </div>
            </Modal>
        );
    }
}

export class ChangeReplRoleModal extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            showConfirmPromote: false,
            showConfirmDemote: false,
        };
    }

    render() {
        const {
            showModal,
            closeHandler,
            handleChange,
            saveHandler,
            role,
            spinning,
            checked,
            onMinus,
            onNumberChange,
            onPlus,
            newRID,
        } = this.props;
        let spinner = "";
        let changeType = "";
        let roleOptions = [];
        let ridRow = "";
        const newRole = this.props.newRole;
        let saveDisabled = !checked;

        // Set the change type
        if (role === "Supplier") {
            changeType = "Demoting";
            roleOptions = ["Hub", "Consumer"];
        } else if (role === "Consumer") {
            changeType = "Promoting";
            roleOptions = ["Supplier", "Hub"];
        } else {
            // Hub
            if (newRole === "Supplier") {
                changeType = "Promoting";
            } else {
                changeType = "Demoting";
            }
            roleOptions = ["Supplier", "Consumer"];
        }
        if (newRole === "Supplier") {
            ridRow = (
                <Grid className="ds-margin-top-lg" title={_("Supplier Replica Identifier.  This must be unique across all the Supplier replicas in your environment")}>
                    <GridItem className="ds-label" span={3}>
                        {_("Replica ID")}
                    </GridItem>
                    <GridItem span={2}>
                        <NumberInput
                            value={newRID}
                            min={1}
                            max={65534}
                            onMinus={onMinus}
                            onChange={onNumberChange}
                            onPlus={onPlus}
                            inputName="input"
                            inputAriaLabel="number input"
                            minusBtnAriaLabel="minus"
                            plusBtnAriaLabel="plus"
                            widthChars={8}
                        />
                    </GridItem>
                </Grid>
            );
        }

        if (spinning) {
            spinner = (
                <Grid>
                    <div className="ds-margin-top ds-modal-spinner">
                        <Spinner size="md" />{changeType} replica ...
                    </div>
                </Grid>
            );
            saveDisabled = true;
        }

        return (
            <Modal
                variant={ModalVariant.small}
                title={_("Change Replica Role")}
                isOpen={showModal}
                aria-labelledby="ds-modal"
                onClose={closeHandler}
                actions={[
                    <Button
                        key="change"
                        variant="primary"
                        onClick={() => {
                            saveHandler(changeType);
                        }}
                        isDisabled={saveDisabled}
                    >
                        {_("Change Role")}
                    </Button>,
                    <Button key="cancel" variant="link" onClick={closeHandler}>
                        {_("Cancel")}
                    </Button>
                ]}
            >
                <Form isHorizontal autoComplete="off">
                    <TextContent>
                        <Text component={TextVariants.h3}>
                            {_("Please choose the new replication role you would like for this suffix")}
                        </Text>
                    </TextContent>
                    <Grid className="ds-margin-top-lg">
                        <GridItem className="ds-label" span={3}>
                            {_("New Role")}
                        </GridItem>
                        <GridItem span={3}>
                            <FormSelect
                                value={newRole}
                                id="newRole"
                                onChange={(e, str) => {
                                    handleChange(e);
                                }}
                                aria-label="FormSelect Input"
                            >
                                {roleOptions.map((option, index) => (
                                    <FormSelectOption key={index} value={option} label={option} />
                                ))}
                            </FormSelect>
                        </GridItem>
                    </Grid>
                    {ridRow}
                    <Grid className="ds-margin-top-xlg">
                        <GridItem span={12} className="ds-center">
                            <Checkbox
                                id="modalChecked"
                                isChecked={checked}
                                onChange={(e, checked) => {
                                    handleChange(e);
                                }}
                                label={<><b>{_("Yes")}</b>{_(", I am sure.")}</>}
                            />
                        </GridItem>
                    </Grid>
                    {spinner}
                </Form>
            </Modal>
        );
    }
}

export class AddEditManagerModal extends React.Component {
    render() {
        const {
            showModal,
            closeHandler,
            handleChange,
            saveHandler,
            spinning,
            manager,
            manager_passwd,
            manager_passwd_confirm,
            error,
            edit,
        } = this.props;
        let saveBtnName = this.props.edit ? "Save Replication Manager" : _("Add Replication Manager");
        const extraPrimaryProps = {};
        if (spinning) {
            saveBtnName = this.props.edit ? "Saving Replication Manager ..." : _("Adding Replication Manager ...");
        }

        return (
            <Modal
                variant={ModalVariant.medium}
                title={this.props.edit ? "Edit Replication Manager" : _("Add Replication Manager")}
                aria-labelledby="ds-modal"
                isOpen={showModal}
                onClose={closeHandler}
                actions={[
                    <Button
                        key="confirm"
                        variant="primary"
                        onClick={saveHandler}
                        isLoading={spinning}
                        spinnerAriaValueText={spinning ? _("Saving") : undefined}
                        {...extraPrimaryProps}
                        isDisabled={error.manager || error.manager_passwd || error.manager_passwd_confirm || spinning}
                    >
                        {saveBtnName}
                    </Button>,
                    <Button key="cancel" variant="link" onClick={closeHandler}>
                        {_("Cancel")}
                    </Button>
                ]}
            >
                <Form isHorizontal autoComplete="off">
                    <TextContent>
                        <Text component={TextVariants.h3}>
                            {this.props.edit ?
                                ""
                            :
                                _("Create a Replication Manager entry, and add it to the replication configuration for this suffix.  If the entry already exists it will be overwritten with the new credentials.")}
                        </Text>
                    </TextContent>
                    <Grid className="ds-margin-top-lg" title={_("The DN of the replication manager")}>
                        <GridItem className="ds-label" span={3}>
                            {_("Replication Manager DN")}
                        </GridItem>
                        <GridItem span={9}>
                            <TextInput
                                value={manager}
                                type="text"
                                id="manager"
                                aria-describedby="horizontal-form-name-helper"
                                name="manager"
                                onChange={(e, str) => {
                                    handleChange(e);
                                }}
                                isDisabled={this.props.edit}
                                validated={error.manager ? ValidatedOptions.error : ValidatedOptions.default}
                            />
                        </GridItem>
                    </Grid>
                    <Grid className="ds-margin-top" title={_("Replication Manager password")}>
                        <GridItem className="ds-label" span={3}>
                            {this.props.edit ? "New password" : _("Password")}
                        </GridItem>
                        <GridItem span={9}>
                            <TextInput
                                value={manager_passwd}
                                type="password"
                                id="manager_passwd"
                                aria-describedby="horizontal-form-name-helper"
                                name="manager_passwd"
                                onChange={(e, str) => {
                                    handleChange(e);
                                }}
                                validated={error.manager_passwd ? ValidatedOptions.error : ValidatedOptions.default}
                            />
                        </GridItem>
                    </Grid>
                    <Grid className="ds-margin-top" title={_("Replication Manager password")}>
                        <GridItem className="ds-label" span={3}>
                            {this.props.edit ? "Confirm new password" : _("Confirm Password")}
                        </GridItem>
                        <GridItem span={9}>
                            <TextInput
                                value={manager_passwd_confirm}
                                type="password"
                                id="manager_passwd_confirm"
                                aria-describedby="horizontal-form-name-helper"
                                name="manager_passwd_confirm"
                                onChange={(e, str) => {
                                    handleChange(e);
                                }}
                                validated={error.manager_passwd_confirm ? ValidatedOptions.error : ValidatedOptions.default}
                            />
                        </GridItem>
                    </Grid>
                </Form>
            </Modal>
        );
    }
}

export class EnableReplModal extends React.Component {
    render() {
        const {
            showModal,
            closeHandler,
            handleChange,
            saveHandler,
            spinning,
            enableRole,
            enableRID,
            enableBindDN,
            enableBindPW,
            enableBindPWConfirm,
            enableBindGroupDN,
            error,
            onMinus,
            onPlus,
            onNumberChange
        } = this.props;
        let saveBtnName = _("Enable Replication");
        const extraPrimaryProps = {};
        if (spinning) {
            saveBtnName = _("Enabling Replication ...");
            extraPrimaryProps.spinnerAriaValueText = _("Saving");
        }
        let replicaIDRow = "";
        if (enableRole === "Supplier") {
            replicaIDRow = (
                <Grid>
                    <GridItem span={3} className="ds-label">
                        {_("Replica ID")}
                    </GridItem>
                    <GridItem span={2}>
                        <NumberInput
                            value={enableRID}
                            min={1}
                            max={65534}
                            onMinus={onMinus}
                            onChange={onNumberChange}
                            onPlus={onPlus}
                            inputName="input"
                            inputAriaLabel="number input"
                            minusBtnAriaLabel="minus"
                            plusBtnAriaLabel="plus"
                            widthChars={6}
                        />
                    </GridItem>
                </Grid>
            );
        }

        return (
            <Modal
                variant={ModalVariant.medium}
                title={_("Enable Replication")}
                aria-labelledby="ds-modal"
                isOpen={showModal}
                onClose={closeHandler}
                actions={[
                    <Button
                        key="enable"
                        variant="primary"
                        onClick={saveHandler}
                        isDisabled={this.props.disabled || spinning}
                        isLoading={spinning}
                        spinnerAriaValueText={spinning ? _("Saving") : undefined}
                        {...extraPrimaryProps}
                    >
                        {saveBtnName}
                    </Button>,
                    <Button key="cancel" variant="link" onClick={closeHandler}>
                        {_("Cancel")}
                    </Button>
                ]}
            >
                <Form isHorizontal autoComplete="off">
                    <TextContent>
                        <Text component={TextVariants.h6}>
                            {_("Choose the replication role for this suffix.  If it is a Supplier replica then you must pick a unique ID to identify it among the other Supplier replicas in your environment.  The replication changelog will also automatically be created for you.")}
                        </Text>
                    </TextContent>
                    <Grid>
                        <GridItem span={3} className="ds-label">
                            {_("Replication Role")}
                        </GridItem>
                        <GridItem span={2}>
                            <FormSelect
                                id="enableRole"
                                value={enableRole}
                                onChange={(e, str) => {
                                    handleChange(e);
                                }}
                                aria-label="FormSelect Input"
                            >
                                <FormSelectOption key={0} value="Supplier" label={_("Supplier")} />
                                <FormSelectOption key={1} value="Hub" label={_("Hub")} />
                                <FormSelectOption key={2} value="Consumer" label={_("Consumer")} />
                            </FormSelect>
                        </GridItem>
                    </Grid>
                    {replicaIDRow}
                    <hr />
                    <TextContent>
                        <Text component={TextVariants.h6}>
                            {_("You can optionally define the authentication information for this replicated suffix.  Either a Manager DN and Password, a Bind Group DN, or both, can be provided.  The Manager DN should be an entry under \"cn=config\" and if it does not exist it will be created, while the Bind Group DN is usually an existing group located in the database suffix.  Typically, just the Manager DN and Password are used when enabling replication for a suffix.")}
                        </Text>
                    </TextContent>
                    <Grid title={_("The DN of the replication manager.  If you supply a password the entry will be created in the server (it will also overwrite the entry is it already exists).")}>
                        <GridItem className="ds-label" span={3}>
                            {_("Replication Manager DN")}
                        </GridItem>
                        <GridItem span={9}>
                            <TextInput
                                value={enableBindDN}
                                type="text"
                                id="enableBindDN"
                                aria-describedby="horizontal-form-name-helper"
                                name="enableBindDN"
                                onChange={(e, str) => {
                                    handleChange(e);
                                }}
                                validated={error.enableBindDN ? ValidatedOptions.error : ValidatedOptions.default}
                            />
                        </GridItem>
                    </Grid>
                    <Grid title={_("Replication Manager password")}>
                        <GridItem className="ds-label" span={3}>
                            {_("Password")}
                        </GridItem>
                        <GridItem span={9}>
                            <TextInput
                                value={enableBindPW}
                                type="password"
                                id="enableBindPW"
                                aria-describedby="horizontal-form-name-helper"
                                name="enableBindPW"
                                onChange={(e, str) => {
                                    handleChange(e);
                                }}
                                validated={error.enableBindPW ? ValidatedOptions.error : ValidatedOptions.default}
                            />
                        </GridItem>
                    </Grid>
                    <Grid title={_("Confirm the Replication Manager password")}>
                        <GridItem className="ds-label" span={3}>
                            {_("Confirm Password")}
                        </GridItem>
                        <GridItem span={9}>
                            <TextInput
                                value={enableBindPWConfirm}
                                type="password"
                                id="enableBindPWConfirm"
                                aria-describedby="horizontal-form-name-helper"
                                name="enableBindPWConfirm"
                                onChange={(e, str) => {
                                    handleChange(e);
                                }}
                                validated={error.enableBindPWConfirm ? ValidatedOptions.error : ValidatedOptions.default}
                            />
                        </GridItem>
                    </Grid>
                    <Grid title={_("The DN of a group that contains users that can perform replication updates")}>
                        <GridItem className="ds-label" span={3}>
                            {_("Bind Group DN")}
                        </GridItem>
                        <GridItem span={9}>
                            <TextInput
                                value={enableBindGroupDN}
                                type="text"
                                id="enableBindGroupDN"
                                aria-describedby="horizontal-form-name-helper"
                                name="enableBindGroupDN"
                                onChange={(e, str) => {
                                    handleChange(e);
                                }}
                                validated={error.enableBindGroupDN ? ValidatedOptions.error : ValidatedOptions.default}
                            />
                        </GridItem>
                    </Grid>
                </Form>
            </Modal>
        );
    }
}

export class ExportCLModal extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            default: true,
            debug: false,
        };
    }

    render() {
        const {
            showModal,
            closeHandler,
            handleChange,
            handleLDIFChange,
            handleRadioChange,
            saveHandler,
            spinning,
            defaultCL,
            debugCL,
            decodeCL,
            exportCSN,
            ldifFile,
            saveOK
        } = this.props;
        let page = "";
        let saveBtnName = _("Export Changelog");
        const extraPrimaryProps = {};
        if (spinning) {
            saveBtnName = _("Exporting ...");
            extraPrimaryProps.spinnerAriaValueText = _("Saving");
        }

        if (defaultCL) {
            page = (
                <TextContent>
                    <Text component={TextVariants.h4}>
                        {_("This will export the changelog to the server's LDIF directory.  This is the only LDIF file that can be imported into the server for enabling changelog encryption.  Do not edit or rename the file.")}
                    </Text>
                </TextContent>
            );
        } else {
            page = (
                <div>
                    <Grid>
                        <GridItem span={12}>
                            <TextContent>
                                <Text component={TextVariants.h4}>
                                    {_("The LDIF file that is generated should <b>not</b> be used to initialize the Replication Changelog.  It is only meant for debugging/investigative purposes.")}
                                </Text>
                            </TextContent>
                        </GridItem>
                    </Grid>
                    <Grid className="ds-margin-top-xlg">
                        <GridItem className="ds-label" span={2}>
                            {_("LDIF File")}
                        </GridItem>
                        <GridItem span={10}>
                            <TextInput
                                value={ldifFile}
                                type="text"
                                id="ldifFile"
                                aria-describedby="horizontal-form-name-helper"
                                name="ldifFile"
                                onChange={(e, str) => {
                                    handleLDIFChange(e);
                                }}
                            />
                        </GridItem>
                    </Grid>
                    <Grid className="ds-margin-top-xlg ds-margin-left">
                        <Checkbox
                            id="decodeCL"
                            isChecked={decodeCL}
                            isDisabled={exportCSN}
                            onChange={(e, checked) => {
                                handleChange(e);
                            }}
                            label={_("Decode base64 changes")}
                        />
                    </Grid>
                    <Grid className="ds-margin-top ds-margin-left">
                        <Checkbox
                            id="exportCSN"
                            isChecked={exportCSN}
                            isDisabled={decodeCL}
                            onChange={(e, checked) => {
                                handleChange(e);
                            }}
                            label={_("Only Export CSN's")}
                        />
                    </Grid>
                </div>
            );
        }

        return (
            <Modal
                variant={ModalVariant.medium}
                className="ds-modal-changelog-export"
                title={_("Create Replication Change Log LDIF File")}
                isOpen={showModal}
                aria-labelledby="ds-modal"
                onClose={closeHandler}
                actions={[
                    <Button
                        key="export"
                        variant="primary"
                        onClick={saveHandler}
                        isDisabled={!saveOK || spinning}
                        isLoading={spinning}
                        spinnerAriaValueText={spinning ? _("Saving") : undefined}
                        {...extraPrimaryProps}
                    >
                        {saveBtnName}
                    </Button>,
                    <Button key="cancel" variant="link" onClick={closeHandler}>
                        {_("Cancel")}
                    </Button>
                ]}
            >
                <Form isHorizontal autoComplete="off">
                    <Grid className="ds-indent ds-margin-top">
                        <Radio
                            isChecked={defaultCL}
                            name="radioGroup"
                            onChange={handleRadioChange}
                            label={_("Export to LDIF For Reinitializing The Changelog")}
                            id="defaultCL"
                        />
                    </Grid>
                    <Grid className="ds-indent">
                        <Radio
                            isChecked={debugCL}
                            name="radioGroup"
                            onChange={handleRadioChange}
                            label={_("Export to LDIF For Debugging")}
                            id="debugCL"
                        />
                    </Grid>
                    <hr />
                    {page}
                </Form>
            </Modal>
        );
    }
}

EnableReplModal.propTypes = {
    showModal: PropTypes.bool,
    closeHandler: PropTypes.func,
    handleChange: PropTypes.func,
    saveHandler: PropTypes.func,
    spinning: PropTypes.bool,
    disabled: PropTypes.bool,
    error: PropTypes.object,
};

EnableReplModal.defaultProps = {
    showModal: false,
    spinning: false,
    disabled: false,
    error: {},
};

AddEditManagerModal.propTypes = {
    showModal: PropTypes.bool,
    closeHandler: PropTypes.func,
    handleChange: PropTypes.func,
    saveHandler: PropTypes.func,
    spinning: PropTypes.bool,
    error: PropTypes.object,
    edit: PropTypes.bool,
};

AddEditManagerModal.defaultProps = {
    showModal: false,
    spinning: false,
    error: {},
};

ChangeReplRoleModal.propTypes = {
    showModal: PropTypes.bool,
    closeHandler: PropTypes.func,
    handleChange: PropTypes.func,
    saveHandler: PropTypes.func,
    spinning: PropTypes.bool,
    role: PropTypes.string,
    newRole: PropTypes.string,
};

ChangeReplRoleModal.defaultProps = {
    showModal: false,
    spinning: false,
    role: "",
    newRole: "",
};

ReplAgmtModal.propTypes = {
    showModal: PropTypes.bool,
    closeHandler: PropTypes.func,
    handleChange: PropTypes.func,
    handleStripChange: PropTypes.func,
    handleFracChange: PropTypes.func,
    handleFracInitChange: PropTypes.func,
    saveHandler: PropTypes.func,
    spinning: PropTypes.bool,
    availAttrs: PropTypes.array,
    agmtName: PropTypes.string,
    agmtHost: PropTypes.string,
    agmtPort: PropTypes.string,
    agmtProtocol: PropTypes.string,
    agmtBindMethod: PropTypes.string,
    agmtBindDN: PropTypes.string,
    agmtBindPW: PropTypes.string,
    agmtBindPWConfirm: PropTypes.string,
    agmtBootstrap: PropTypes.bool,
    agmtBootstrapProtocol: PropTypes.string,
    agmtBootstrapBindMethod: PropTypes.string,
    agmtBootstrapBindDN: PropTypes.string,
    agmtBootstrapBindPW: PropTypes.string,
    agmtBootstrapBindPWConfirm: PropTypes.string,
    agmtStripAttrs: PropTypes.array,
    agmtFracAttrs: PropTypes.array,
    agmtFracInitAttrs: PropTypes.array,
    agmtSync: PropTypes.bool,
    agmtSyncMon: PropTypes.bool,
    agmtSyncTue: PropTypes.bool,
    agmtSyncWed: PropTypes.bool,
    agmtSyncThu: PropTypes.bool,
    agmtSyncFri: PropTypes.bool,
    agmtSyncSat: PropTypes.bool,
    agmtSyncSun: PropTypes.bool,
    agmtStartTime: PropTypes.string,
    agmtEndTime: PropTypes.string,
    saveOK: PropTypes.bool,
    error: PropTypes.object,
    edit: PropTypes.bool,
};

ReplAgmtModal.defaultProps = {
    showModal: false,
    spinning: false,
    availAttrs: [],
    agmtName: "",
    agmtHost: "",
    agmtPort: "636",
    agmtProtocol: "LDAP",
    agmtBindMethod: "SIMPLE",
    agmtBindDN: "",
    agmtBindPW: "",
    agmtBindPWConfirm: "",
    agmtBootstrap: false,
    agmtBootstrapProtocol: "LDAP",
    agmtBootstrapBindMethod: "SIMPLE",
    agmtBootstrapBindDN: "",
    agmtBootstrapBindPW: "",
    agmtBootstrapBindPWConfirm: "",
    agmtStripAttrs: [],
    agmtFracAttrs: [],
    agmtFracInitAttrs: [],
    agmtSync: true,
    agmtSyncMon: false,
    agmtSyncTue: false,
    agmtSyncWed: false,
    agmtSyncThu: false,
    agmtSyncFri: false,
    agmtSyncSat: false,
    agmtSyncSun: false,
    agmtStartTime: "00:00",
    agmtEndTime: "23:59",
    saveOK: false,
    error: {},
    edit: false,
};

WinsyncAgmtModal.propTypes = {
    showModal: PropTypes.bool,
    closeHandler: PropTypes.func,
    handleChange: PropTypes.func,
    handleFracChange: PropTypes.func,
    saveHandler: PropTypes.func,
    spinning: PropTypes.bool,
    availAttrs: PropTypes.array,
    agmtName: PropTypes.string,
    agmtHost: PropTypes.string,
    agmtPort: PropTypes.string,
    agmtProtocol: PropTypes.string,
    agmtBindDN: PropTypes.string,
    agmtBindPW: PropTypes.string,
    agmtBindPWConfirm: PropTypes.string,
    agmtFracAttrs: PropTypes.array,
    agmtSync: PropTypes.bool,
    agmtSyncMon: PropTypes.bool,
    agmtSyncTue: PropTypes.bool,
    agmtSyncWed: PropTypes.bool,
    agmtSyncThu: PropTypes.bool,
    agmtSyncFri: PropTypes.bool,
    agmtSyncSat: PropTypes.bool,
    agmtSyncSun: PropTypes.bool,
    agmtStartTime: PropTypes.string,
    agmtEndTime: PropTypes.string,
    agmtSyncGroups: PropTypes.bool,
    agmtSyncUsers: PropTypes.bool,
    agmtWinDomain: PropTypes.string,
    agmtWinSubtree: PropTypes.string,
    agmtDSSubtree: PropTypes.string,
    agmtOneWaySync: PropTypes.string,
    agmtSyncInterval: PropTypes.string,
    saveOK: PropTypes.bool,
    error: PropTypes.object,
    edit: PropTypes.bool,
};

WinsyncAgmtModal.defaultProps = {
    showModal: false,
    spinning: false,
    availAttrs: [],
    agmtName: "",
    agmtHost: "",
    agmtPort: "636",
    agmtProtocol: "LDAPS",
    agmtBindDN: "",
    agmtBindPW: "",
    agmtBindPWConfirm: "",
    agmtFracAttrs: [],
    agmtSync: true,
    agmtSyncMon: false,
    agmtSyncTue: false,
    agmtSyncWed: false,
    agmtSyncThu: false,
    agmtSyncFri: false,
    agmtSyncSat: false,
    agmtSyncSun: false,
    agmtStartTime: "00:00",
    agmtEndTime: "23:59",
    agmtSyncGroups: false,
    agmtSyncUsers: false,
    agmtWinDomain: "",
    agmtWinSubtree: "",
    agmtDSSubtree: "",
    agmtOneWaySync: "both", // "both", "toWindows", "fromWindows"
    agmtSyncInterval: "",
    saveOK: false,
    error: {},
    edit: false,
};
