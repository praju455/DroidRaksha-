package com.droidraksha.mobile.data.remote

import com.droidraksha.mobile.data.remote.dto.DeepScanRequest
import com.droidraksha.mobile.data.remote.dto.DeepScanResponse
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.POST

interface DeepScanApi {

    @POST("/check-ioc")
    suspend fun checkIoc(
        @Body request: DeepScanRequest
    ): Response<DeepScanResponse>
}
