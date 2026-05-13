package wafqueue

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/wafipban"
	"SamWaf/waftask"
	"strconv"
	"time"
)

/*
*
处理Log队列信息
*/
func ProcessLogDequeEngine() {
	loopCount := 0
	for {
		loopCount++
		select {
		case <-global.GWAF_QUEUE_SHUTDOWN_SIGNAL:
			zlog.Info("日志队列处理协程收到关闭信号，正在退出...")
			return
		default:
			global.GWAF_MEASURE_PROCESS_DEQUEENGINE.WriteData(time.Now().UnixNano() / 1e6)
			if global.GDATA_CURRENT_CHANGE {
				//如果正在切换库 跳过
				if loopCount%100 == 1 {
					zlog.Warn("日志队列诊断: GDATA_CURRENT_CHANGE=true，队列处理器被阻塞！",
						"loop", loopCount, "persist_enable", global.GCONFIG_LOG_PERSIST_ENABLED)
				}

			} else {
				var webLogArray []*innerbean.WebLog
				batchCount := 0
				for !global.GQEQUE_LOG_DB.Empty() {
					global.IncrementLogQPS() // 使用统一的日志QPS增量函数
					weblogbean, ok := global.GQEQUE_LOG_DB.Dequeue()
					if !ok {
						continue
					}
					if weblogbean != nil {
						// 进行类型断言将其转为具体的结构
						if logValue, ok := weblogbean.(*innerbean.WebLog); ok {
							webLogArray = append(webLogArray, logValue)
							batchCount++
							if batchCount > int(global.GDATA_BATCH_INSERT) {
								break
							}
						} else {
							//插入其他类型内容
							global.GWAF_LOCAL_LOG_DB.Create(weblogbean)
						}
					}
				}
				if len(webLogArray) > 0 {
					zlog.Info("日志队列处理日志数量:" + strconv.Itoa(len(webLogArray)) +
						" persist_enable:" + strconv.FormatInt(global.GCONFIG_LOG_PERSIST_ENABLED, 10))
					// 检查失败状态码并记录IP失败
					if global.GCONFIG_IP_FAILURE_BAN_ENABLED == 1 {
						ipManager := wafipban.GetIPFailureManager()
						for _, log := range webLogArray {
							if ipManager.IsFailureStatusCode(log.STATUS_CODE) {
								ipManager.RecordFailure(log)
							}
						}
					}
					if global.GCONFIG_LOG_PERSIST_ENABLED == 1 {
						err := global.GWAF_LOCAL_LOG_DB.CreateInBatches(webLogArray, len(webLogArray)).Error
						if err != nil {
							zlog.Error("日志队列写入数据库失败!", "err", err.Error(), "count", len(webLogArray))
						}
					} else {
						if loopCount%100 == 1 {
							zlog.Warn("日志队列诊断: GCONFIG_LOG_PERSIST_ENABLED=0，日志不入库！",
								"loop", loopCount, "batch_count", len(webLogArray))
						}
					}
					// 日志流做统计
					waftask.CollectStatsFromLogs(webLogArray)
					global.GNOTIFY_KAKFA_SERVICE.ProcessBatchLogs(webLogArray)
					// 文件日志写入
					global.GNOTIFY_LOG_FILE_WRITER.ProcessBatchLogs(webLogArray)
				}
			}
			// 每100次循环输出诊断信息
			if loopCount%100 == 1 && !global.GDATA_CURRENT_CHANGE {
				queueSize := global.GQEQUE_LOG_DB.Size()
				if queueSize > 0 {
					zlog.Info("日志队列诊断: 队列堆积",
						"loop", loopCount, "queue_size", queueSize,
						"persist_enable", global.GCONFIG_LOG_PERSIST_ENABLED,
						"batch_insert", global.GDATA_BATCH_INSERT)
				}
			}
			time.Sleep(100 * time.Millisecond)
			global.GWAF_MEASURE_PROCESS_DEQUEENGINE.WriteData(time.Now().UnixNano() / 1e6)
		}
	}
}
