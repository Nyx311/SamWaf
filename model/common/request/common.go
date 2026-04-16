package request

const MaxPageSize = 100 // 最大每页条数限制，防止一次查询加载过多数据导致内存溢出

type PageInfo struct {
	PageIndex int    `json:"pageIndex" form:"pageIndex"` //当前页面索引
	PageSize  int    `json:"pageSize" form:"pageSize"`   // 每页大小
	Keyword   string `json:"keyWord" form:"keyWord"`     //关键字
}

// ClampPageSize 确保 PageSize 在合理范围内，防止过大查询导致内存溢出
func (p *PageInfo) ClampPageSize() {
	if p.PageSize <= 0 {
		p.PageSize = 10
	} else if p.PageSize > MaxPageSize {
		p.PageSize = MaxPageSize
	}
	if p.PageIndex <= 0 {
		p.PageIndex = 1
	}
}
