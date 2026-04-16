package waf_service

import (
	"SamWaf/common/validfield"
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model/request"
	"SamWaf/wafdb"
	"errors"
	"strconv"
	"strings"
)

type WafLogService struct{}

var WafLogServiceApp = new(WafLogService)

func (receiver *WafLogService) AddApi(log innerbean.WebLog) error {
	global.GWAF_LOCAL_LOG_DB.Create(log)
	return nil
}
func (receiver *WafLogService) ModifyApi(log innerbean.WebLog) error {
	return nil
}
func (receiver *WafLogService) GetDetailApi(req request.WafAttackLogDetailReq) (innerbean.WebLog, error) {
	var weblog innerbean.WebLog
	if len(req.CurrrentDbName) == 0 || req.CurrrentDbName == "local_log.db" {
		global.GWAF_LOCAL_LOG_DB.Where("REQ_UUID=?", req.REQ_UUID).Find(&weblog)
	} else {
		wafdb.InitManaulLogDb("", req.CurrrentDbName)
		global.GDATA_CURRENT_LOG_DB_MAP[req.CurrrentDbName].Where("REQ_UUID=?", req.REQ_UUID).Find(&weblog)
	}

	return weblog, nil
}
func (receiver *WafLogService) GetListApi(req request.WafAttackLogSearch) ([]innerbean.WebLog, int64, error) {
	req.ClampPageSize()
	var total int64 = 0
	var weblogs []innerbean.WebLog

	splitFilterBys := strings.Split(req.FilterBy, "|")
	splitFilterValues := strings.Split(req.FilterValue, "|")
	/*寮哄埗绱㈠紩*/
	var forceIndex = "web_logs"
	/*where鏉′欢*/
	var whereField = ""
	var whereValues []interface{}

	//where瀛楁
	{
		whereField = whereField + " (unix_add_time>=? and unix_add_time<=?)"
		if len(req.HostCode) > 0 {
			if len(whereField) > 0 {
				whereField = whereField + " and "
			}
			whereField = whereField + " host_code=? "
		}
		if len(req.Rule) > 0 {
			if len(whereField) > 0 {
				whereField = whereField + " and "
			}
			whereField = whereField + " rule=? "
		}
		if len(req.ReqUuid) > 0 {
			if len(whereField) > 0 {
				whereField = whereField + " and "
			}
			whereField = whereField + " req_uuid=? "
		}
		if len(req.Action) > 0 {
			if len(whereField) > 0 {
				whereField = whereField + " and "
			}
			whereField = whereField + " action=? "
		}
		if len(req.SrcIp) > 0 {
			if len(whereField) > 0 {
				whereField = whereField + " and "
			}
			whereField = whereField + " src_ip=? "
		}
		if len(req.StatusCode) > 0 {
			if len(whereField) > 0 {
				whereField = whereField + " and "
			}
			whereField = whereField + " status_code=? "
		}
		if len(req.Method) > 0 {
			if len(whereField) > 0 {
				whereField = whereField + " and "
			}
			whereField = whereField + " method=? "
		}
		if len(req.LogOnlyMode) > 0 {
			if len(whereField) > 0 {
				whereField = whereField + " and "
			}
			whereField = whereField + " log_only_mode=? "
		}
		for _, by := range splitFilterBys {

			if len(by) > 0 {
				if !validfield.IsValidWebLogFilterField(by) {
					return nil, 0, errors.New("杈撳叆杩囨护瀛楁涓嶅悎娉?)
				}
				if len(whereField) > 0 {
					whereField = whereField + " and "
				}
				if by == "guest_identification" {
					by = "guest_id_entification"
				}
				whereField = whereField + " " + by + " like ? "
			}
		}
	}
	//寮哄埗绱㈠紩
	{
		if strings.Contains(whereField, "unix_add_time") && !strings.Contains(whereField, "src_ip") {
			forceIndex = "web_logs INDEXED BY  idx_web_time_desc_tenant_user_code"
		} else if strings.Contains(whereField, "src_ip") {
			forceIndex = "web_logs INDEXED BY  idx_web_time_desc_tenant_user_code_ip"
		}
	}

	// 灏嗗瓧绗︿覆杞崲涓?int64 绫诲瀷
	unixBegin, err := strconv.ParseInt(req.UnixAddTimeBegin, 10, 64)
	if err != nil {
		zlog.Warn("WafLogService parse UnixAddTimeBegin failed", "value", req.UnixAddTimeBegin, "err", err.Error())

	}

	unixEnd, err := strconv.ParseInt(req.UnixAddTimeEnd, 10, 64)
	if err != nil {
		zlog.Warn("WafLogService parse UnixAddTimeEnd failed", "value", req.UnixAddTimeEnd, "err", err.Error())

	}

	//where瀛楁璧嬪€?
	{
		whereValues = append(whereValues, unixBegin)
		whereValues = append(whereValues, unixEnd)
		if len(req.HostCode) > 0 {
			whereValues = append(whereValues, req.HostCode)
		}
		if len(req.Rule) > 0 {
			whereValues = append(whereValues, req.Rule)
		}
		if len(req.ReqUuid) > 0 {
			whereValues = append(whereValues, req.ReqUuid)
		}
		if len(req.Action) > 0 {
			whereValues = append(whereValues, req.Action)
		}
		if len(req.SrcIp) > 0 {
			whereValues = append(whereValues, req.SrcIp)
		}
		if len(req.StatusCode) > 0 {
			whereValues = append(whereValues, req.StatusCode)
		}
		if len(req.Method) > 0 {
			whereValues = append(whereValues, req.Method)
		}
		if len(req.LogOnlyMode) > 0 {
			whereValues = append(whereValues, req.LogOnlyMode)
		}
		for _, val := range splitFilterValues {
			if len(val) > 0 {
				whereValues = append(whereValues, "%"+val+"%")
			}
		}
	}

	orderInfo := ""

	/**
	鎺掑簭
	*/
	if receiver.isValidSortField(req.SortBy) {
		if req.SortDescending == "desc" {
			orderInfo = req.SortBy + " desc"
		} else {
			orderInfo = req.SortBy + " asc"
		}
	} else {
		return nil, 0, errors.New("杈撳叆鎺掑簭瀛楁涓嶅悎娉?)
	}
	zlog.Debug("WafLogService query info", "db", req.CurrrentDbName, "force_index", forceIndex, "where", whereField, "where_value_count", len(whereValues), "unix_begin", unixBegin, "unix_end", unixEnd, "page_index", req.PageIndex, "page_size", req.PageSize, "order", orderInfo)
	if len(req.CurrrentDbName) == 0 || req.CurrrentDbName == "local_log.db" {
		global.GWAF_LOCAL_LOG_DB.Table(forceIndex).Limit(req.PageSize).Where(whereField, whereValues...).Offset(req.PageSize * (req.PageIndex - 1)).Order(orderInfo).Find(&weblogs)
		global.GWAF_LOCAL_LOG_DB.Table(forceIndex).Where(whereField, whereValues...).Count(&total)
	} else {
		wafdb.InitManaulLogDb("", req.CurrrentDbName)
		global.GDATA_CURRENT_LOG_DB_MAP[req.CurrrentDbName].Table(forceIndex).Limit(req.PageSize).Where(whereField, whereValues...).Offset(req.PageSize * (req.PageIndex - 1)).Order(orderInfo).Find(&weblogs)
		global.GDATA_CURRENT_LOG_DB_MAP[req.CurrrentDbName].Table(forceIndex).Where(whereField, whereValues...).Count(&total)

	}
	zlog.Debug("WafLogService query result", "rows", len(weblogs), "total", total)
	return weblogs, total, nil
}
func (receiver *WafLogService) GetListByHostCodeApi(log request.WafAttackLogSearch) ([]innerbean.WebLog, int64, error) {
	log.ClampPageSize()
	var total int64 = 0
	var weblogs []innerbean.WebLog
	global.GWAF_LOCAL_LOG_DB.Where("host_code = ? ", global.GWAF_TENANT_ID, global.GWAF_USER_CODE, log.HostCode).Limit(log.PageSize).Offset(log.PageSize * (log.PageIndex - 1)).Order("create_time desc").Find(&weblogs)
	global.GWAF_LOCAL_LOG_DB.Where("host_code = ? ", global.GWAF_TENANT_ID, global.GWAF_USER_CODE, log.HostCode).Model(&innerbean.WebLog{}).Count(&total)
	return weblogs, total, nil
}
func (receiver *WafLogService) DeleteHistory(day string) {
	global.GWAF_LOCAL_LOG_DB.Where("create_time < ?", day).Delete(&innerbean.WebLog{})
}

// GetUnixTimeByCounter 渚濇嵁寮€濮嬫椂闂村拰鍒版湡鏃堕棿鑾峰彇涓€涓渶鏂扮殑鏃堕棿鎴?
func (receiver *WafLogService) GetUnixTimeByCounter(lastStartCreateUnix int64, lastEndCreateUnix int64) innerbean.WebLog {
	var weblog innerbean.WebLog
	forceIndex := "web_logs INDEXED BY  idx_web_time_desc_tenant_user_code"
	global.GWAF_LOCAL_LOG_DB.Table(forceIndex).Where("unix_add_time>=? and unix_add_time<?", lastStartCreateUnix, lastEndCreateUnix).Order("unix_add_time desc").Limit(1).Find(&weblog)

	return weblog
}

/*
*
鍒ゆ柇鏄惁鍚堟硶
*/
func (receiver *WafLogService) isValidSortField(field string) bool {
	var allowedSortFields = []string{"time_spent", "create_time", "unix_add_time"}

	for _, allowedField := range allowedSortFields {
		if field == allowedField {
			return true
		}
	}
	return false
}
