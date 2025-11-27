use cosmwasm_schema::cw_serde;

use cosmwasm_std::{
    to_json_binary, Addr, CosmosMsg, CustomQuery, Querier, QuerierWrapper, StdResult, WasmMsg,
    WasmQuery,
};

use crate::msg::{ExecuteMsg, GetChannelResponse, QueryMsg};

/// PaymentChannelContract is a wrapper around Addr that provides helpers
/// for working with the payment channel contract.
#[cw_serde]
pub struct PaymentChannelContract(pub Addr);

impl PaymentChannelContract {
    pub fn addr(&self) -> Addr {
        self.0.clone()
    }

    pub fn call<T: Into<ExecuteMsg>>(&self, msg: T) -> StdResult<CosmosMsg> {
        let msg = to_json_binary(&msg.into())?;
        Ok(WasmMsg::Execute {
            contract_addr: self.addr().into(),
            msg,
            funds: vec![],
        }
        .into())
    }

    /// Get Channel
    pub fn get_channel<Q, CQ>(
        &self,
        querier: &Q,
        channel_id: String,
    ) -> StdResult<GetChannelResponse>
    where
        Q: Querier,
        CQ: CustomQuery,
    {
        let msg = QueryMsg::GetChannel { channel_id };
        let query = WasmQuery::Smart {
            contract_addr: self.addr().into(),
            msg: to_json_binary(&msg)?,
        }
        .into();
        let res: GetChannelResponse = QuerierWrapper::<CQ>::new(querier).query(&query)?;
        Ok(res)
    }
}
