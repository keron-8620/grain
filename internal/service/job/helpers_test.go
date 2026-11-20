package job

import (
	"testing"

	"github.com/stretchr/testify/assert"

	biz "grain/internal/biz/job"
)

func TestValidateEnvVars(t *testing.T) {
	assert.NoError(t, validateEnvVars(""))
	assert.NoError(t, validateEnvVars(`{"MODE":"full","RETRIES":"3"}`))

	assert.Error(t, validateEnvVars(`["MODE"]`))
	assert.Error(t, validateEnvVars(`{"MODE":1}`))
	assert.Error(t, validateEnvVars(`{"1MODE":"x"}`))
	assert.Error(t, validateEnvVars(`{"BAD-NAME":"x"}`))
	assert.Error(t, validateEnvVars(`not-json`))
}

func TestScriptStatusText(t *testing.T) {
	assert.Equal(t, "pending", scriptStatusText(biz.ScriptRecordStatusPending))
	assert.Equal(t, "running", scriptStatusText(biz.ScriptRecordStatusRunning))
	assert.Equal(t, "success", scriptStatusText(biz.ScriptRecordStatusSuccess))
	assert.Equal(t, "failed", scriptStatusText(biz.ScriptRecordStatusFailed))
	assert.Equal(t, "timeout", scriptStatusText(biz.ScriptRecordStatusTimeout))
	assert.Equal(t, "crashed", scriptStatusText(biz.ScriptRecordStatusCrashed))
	assert.Equal(t, "canceled", scriptStatusText(biz.ScriptRecordStatusCancel))
	assert.Equal(t, "unknown", scriptStatusText(biz.ScriptRecordStatus(99)))
}
