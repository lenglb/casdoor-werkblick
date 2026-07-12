// Copyright 2023 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import React from "react";
import {Button, Col, Result, Row, Spin, Steps} from "antd";
import {withRouter} from "react-router-dom";
import * as ApplicationBackend from "../backend/ApplicationBackend";
import * as Setting from "../Setting";
import i18next from "i18next";
import * as MfaBackend from "../backend/MfaBackend";
import {CheckOutlined, KeyOutlined, UserOutlined} from "@ant-design/icons";
import CheckPasswordForm from "./mfa/CheckPasswordForm";
import MfaEnableForm from "./mfa/MfaEnableForm";
import {MfaVerifyForm} from "./mfa/MfaVerifyForm";

export const EmailMfaType = "email";
export const SmsMfaType = "sms";
export const TotpMfaType = "app";
export const RadiusMfaType = "radius";
export const PushMfaType = "push";
export const RecoveryMfaType = "recovery";

const blockedMfaRedirectProtocols = new Set(["about:", "blob:", "data:", "file:", "javascript:", "vbscript:"]);

export function getSafeMfaRedirectUrl(redirectUrl, baseUrl = window.location.origin) {
  if (typeof redirectUrl !== "string" || redirectUrl.trim() === "") {
    return null;
  }

  try {
    const target = new URL(redirectUrl, baseUrl);
    if (blockedMfaRedirectProtocols.has(target.protocol.toLowerCase())) {
      return null;
    }
    return target.toString();
  } catch {
    return null;
  }
}

class MfaSetupPage extends React.Component {
  constructor(props) {
    super(props);
    const params = new URLSearchParams(props.location.search);
    const {location} = this.props;
    const boundApplicationId = props.account.mfaSetupApplicationId || "";
    const applicationIdParts = boundApplicationId.split("/");
    const hasBoundApplication = applicationIdParts.length === 2 && applicationIdParts.every(Boolean);
    this.state = {
      account: props.account,
      application: null,
      applicationOwner: hasBoundApplication ? applicationIdParts[0] : "admin",
      applicationName: hasBoundApplication ? applicationIdParts[1] : (props.account.signupApplication || localStorage.getItem("applicationName") || ""),
      boundApplicationId: hasBoundApplication ? boundApplicationId : "",
      current: location.state?.from !== undefined ? 1 : 0,
      mfaProps: null,
      mfaType: params.get("mfaType") ?? TotpMfaType,
      isPromptPage: props.isPromptPage || location.state?.from !== undefined,
      loading: false,
    };
  }

  componentDidMount() {
    this.getApplication();
    if (this.state.current === 1) {
      this.setState({
        loading: true,
      });

      setTimeout(() => {
        this.initMfaProps();
      }, 200);
    }
  }

  componentDidUpdate(prevProps, prevState, snapshot) {
    if (this.props.location.search !== prevProps.location.search) {
      const requestedMfaType = new URLSearchParams(this.props.location.search).get("mfaType");
      if (requestedMfaType && requestedMfaType !== this.state.mfaType) {
        this.setState({
          mfaType: requestedMfaType,
          mfaProps: null,
          loading: this.state.current === 1,
        });
        return;
      }
    }

    if (this.state.mfaType !== prevState.mfaType || this.state.current !== prevState.current) {
      if (this.state.current === 1) {
        this.initMfaProps();
      }
    }
  }

  getApplication() {
    ApplicationBackend.getApplication(this.state.applicationOwner, this.state.applicationName)
      .then((res) => {
        if (res !== null) {
          if (res.status === "error") {
            Setting.showMessage("error", res.msg);
            return;
          }
          this.setState({
            application: this.state.boundApplicationId ? {
              ...res.data,
              mfaSetupApplicationId: this.state.boundApplicationId,
            } : res.data,
          });
        } else {
          Setting.showMessage("error", i18next.t("general:Failed to get"));
        }
      });
  }

  initMfaProps() {
    MfaBackend.MfaSetupInitiate({
      mfaType: this.state.mfaType,
      ...this.getUser(),
    }).then((res) => {
      if (res.status === "ok") {
        this.setState({
          mfaProps: res.data,
          loading: false,
        });
      } else {
        Setting.showMessage("error", i18next.t("mfa:Failed to initiate MFA"));
      }
    });
  }

  getUser() {
    return this.props.account;
  }

  navigateToMfaRedirect(redirectUrl) {
    const safeRedirectUrl = getSafeMfaRedirectUrl(redirectUrl);
    if (safeRedirectUrl === null) {
      Setting.showMessage("error", "Invalid MFA redirect URL");
      return false;
    }

    localStorage.removeItem("mfaRedirectUrl");
    this.props.onfinish?.();
    Setting.goToLink(safeRedirectUrl);
    return true;
  }

  finishMfaSetup(useStoredRedirect) {
    const storedRedirectUrl = localStorage.getItem("mfaRedirectUrl");
    localStorage.removeItem("mfaRedirectUrl");
    this.props.onfinish?.();

    if (useStoredRedirect && storedRedirectUrl) {
      const safeRedirectUrl = getSafeMfaRedirectUrl(storedRedirectUrl);
      if (safeRedirectUrl !== null) {
        Setting.goToLink(safeRedirectUrl);
        return;
      }
      Setting.showMessage("error", "Invalid MFA redirect URL");
    }

    if (useStoredRedirect) {
      this.props.history.push("/account");
    } else {
      this.props.history.replace("/account");
    }
  }

  handleMfaSetupCompletion(completion) {
    Setting.showMessage("success", i18next.t("general:Enabled successfully"));

    if (completion.responseMode === "form_post" && completion.redirectUri && completion.code) {
      const safeRedirectUrl = getSafeMfaRedirectUrl(completion.redirectUri);
      if (safeRedirectUrl === null) {
        Setting.showMessage("error", "Invalid MFA redirect URL");
        return;
      }
      localStorage.removeItem("mfaRedirectUrl");
      this.props.onfinish?.();
      Setting.createFormAndSubmit(safeRedirectUrl, {
        code: completion.code,
        state: completion.state,
      });
      return;
    }

    if (completion.redirectUrl) {
      this.navigateToMfaRedirect(completion.redirectUrl);
      return;
    }

    switch (completion.type) {
    case "mfa_setup_required":
      // Reloading refreshes the restricted account. App then selects the next
      // still-required factor and updates this route's mfaType.
      window.location.reload();
      return;
    case "complete":
    case "device":
      this.finishMfaSetup(false);
      return;
    case "consent":
    case "oauth_code":
      Setting.showMessage("error", "MFA completion redirect is missing");
      return;
    default:
      // Legacy self-service and admin responses contain no typed completion.
      this.finishMfaSetup(true);
    }
  }

  renderMfaTypeSwitch() {
    return null;
  }

  renderStep() {
    switch (this.state.current) {
    case 0:
      return (
        <CheckPasswordForm
          user={this.getUser()}
          onSuccess={() => {
            this.setState({
              current: this.state.current + 1,
            });
          }}
          onFail={(res) => {
            Setting.showMessage("error", i18next.t("mfa:Failed to initiate MFA") + ": " + res.msg);
          }}
        />
      );
    case 1:
      return (
        <div>
          <MfaVerifyForm
            mfaProps={this.state.mfaProps}
            application={this.state.application}
            user={this.props.account}
            onSuccess={(res) => {
              this.setState({
                dest: res.dest,
                countryCode: res.countryCode,
                current: this.state.current + 1,
              });
            }}
            onFail={(res) => {
              Setting.showMessage("error", i18next.t("general:Failed to verify") + ": " + res.msg);
            }}
          />
          <Col span={24} style={{display: "flex", justifyContent: "center", flexWrap: "wrap"}}>
            {this.renderMfaTypeSwitch()}
          </Col>
        </div>
      );
    case 2:
      return (
        <MfaEnableForm user={this.getUser()} mfaType={this.state.mfaType} secret={this.state.mfaProps.secret} recoveryCodes={this.state.mfaProps.recoveryCodes} dest={this.state.dest} countryCode={this.state.countryCode}
          onSuccess={(res, completion) => {
            this.handleMfaSetupCompletion(completion);
          }}
          onFail={(res) => {
            Setting.showMessage("error", `${i18next.t("general:Failed to enable")}: ${res.msg}`);
          }} />
      );
    default:
      return null;
    }
  }

  render() {
    if (!this.props.account) {
      return (
        <Result
          status="403"
          title="403 Unauthorized"
          subTitle={i18next.t("general:Sorry, you do not have permission to access this page or logged in status invalid.")}
          extra={<a href="/web/public"><Button type="primary">{i18next.t("general:Back Home")}</Button></a>}
        />
      );
    }

    return (
      <Row>
        <Col span={24} style={{justifyContent: "center"}}>
          <Row>
            <Col span={24}>
              <p style={{textAlign: "center", fontSize: "28px"}}>
                {i18next.t("mfa:Protect your account with Multi-factor authentication")}</p>
              <p style={{textAlign: "center", fontSize: "16px", marginTop: "10px"}}>{i18next.t("mfa:Each time you sign in to your Account, you'll need your password and a authentication code")}</p>
            </Col>
          </Row>
          <Spin spinning={this.state.loading}>
            <Steps current={this.state.current}
              items={[
                {title: i18next.t("mfa:Verify Password"), icon: <UserOutlined />},
                {title: i18next.t("mfa:Verify Code"), icon: <KeyOutlined />},
                {title: i18next.t("general:Enable"), icon: <CheckOutlined />},
              ]}
              style={{width: "90%", maxWidth: "500px", margin: "auto", marginTop: "50px",
              }} >
            </Steps>
          </Spin>
        </Col>
        <Col span={24} style={{display: "flex", justifyContent: "center"}}>
          <div style={{marginTop: "10px", textAlign: "center"}}>
            {this.renderStep()}
          </div>
        </Col>
      </Row>
    );
  }
}

export default withRouter(MfaSetupPage);
