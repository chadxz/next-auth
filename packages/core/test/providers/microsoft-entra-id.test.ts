import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import MicrosoftEntraID from "../../src/providers/microsoft-entra-id"
import { customFetch } from "../../src/index"

describe("MicrosoftEntraID", () => {
  it("should have correct default configuration", () => {
    const config = MicrosoftEntraID({
      clientId: "test-client-id",
      clientSecret: "test-client-secret",
    })

    expect(config.id).toBe("microsoft-entra-id")
    expect(config.name).toBe("Microsoft Entra ID")
    expect(config.type).toBe("oidc")
  })

  it("should use default issuer when not provided", () => {
    const originalEnv = process.env.AUTH_MICROSOFT_ENTRA_ID_ISSUER
    delete process.env.AUTH_MICROSOFT_ENTRA_ID_ISSUER

    const config = MicrosoftEntraID({
      clientId: "test-client-id",
      clientSecret: "test-client-secret",
    })

    expect(config.options?.issuer).toBe(
      "https://login.microsoftonline.com/common/v2.0"
    )

    process.env.AUTH_MICROSOFT_ENTRA_ID_ISSUER = originalEnv
  })

  it("should use custom issuer when provided", () => {
    const config = MicrosoftEntraID({
      clientId: "test-client-id",
      clientSecret: "test-client-secret",
      issuer: "https://login.microsoftonline.com/my-tenant-id/v2.0",
    })

    expect(config.options?.issuer).toBe(
      "https://login.microsoftonline.com/my-tenant-id/v2.0"
    )
  })

  describe("clientAssertion", () => {
    it("should set token_endpoint_auth_method to none when clientAssertion is provided", () => {
      const config = MicrosoftEntraID({
        clientId: "test-client-id",
        clientAssertion: async () => "test-assertion",
      })

      expect(config.client?.token_endpoint_auth_method).toBe("none")
    })

    it("should not set token_endpoint_auth_method when clientAssertion is not provided", () => {
      const config = MicrosoftEntraID({
        clientId: "test-client-id",
        clientSecret: "test-client-secret",
      })

      expect(config.client?.token_endpoint_auth_method).toBeUndefined()
    })

    describe("customFetch token endpoint interception", () => {
      beforeEach(() => {
        vi.stubGlobal("fetch", vi.fn())
      })

      afterEach(() => {
        vi.unstubAllGlobals()
      })

      it("should inject client_assertion into token endpoint requests", async () => {
        const mockAssertion = "mock-jwt-assertion"
        const clientAssertionFn = vi.fn().mockResolvedValue(mockAssertion)

        vi.mocked(fetch).mockResolvedValue(
          new Response(JSON.stringify({ access_token: "token" }), {
            status: 200,
          })
        )

        const config = MicrosoftEntraID({
          clientId: "test-client-id",
          issuer: "https://login.microsoftonline.com/test-tenant/v2.0",
          clientAssertion: clientAssertionFn,
        })

        const fetchHandler = config[customFetch]!
        const body = new URLSearchParams({
          client_id: "test-client-id",
          grant_type: "authorization_code",
          code: "auth-code",
        })

        await fetchHandler(
          "https://login.microsoftonline.com/test-tenant/oauth2/v2.0/token",
          { method: "POST", body }
        )

        expect(clientAssertionFn).toHaveBeenCalledOnce()
        expect(body.get("client_assertion_type")).toBe(
          "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        )
        expect(body.get("client_assertion")).toBe(mockAssertion)
        expect(fetch).toHaveBeenCalledWith(
          "https://login.microsoftonline.com/test-tenant/oauth2/v2.0/token",
          expect.objectContaining({ method: "POST", body })
        )
      })

      it("should not inject client_assertion for non-token endpoints", async () => {
        const clientAssertionFn = vi.fn().mockResolvedValue("assertion")

        vi.mocked(fetch).mockResolvedValue(
          new Response(JSON.stringify({ issuer: "https://example.com" }), {
            status: 200,
          })
        )

        const config = MicrosoftEntraID({
          clientId: "test-client-id",
          clientAssertion: clientAssertionFn,
        })

        const fetchHandler = config[customFetch]!
        await fetchHandler("https://example.com/some-other-endpoint", {
          method: "GET",
        })

        expect(clientAssertionFn).not.toHaveBeenCalled()
      })

      it("should not inject client_assertion when body is not URLSearchParams", async () => {
        const clientAssertionFn = vi.fn().mockResolvedValue("assertion")

        vi.mocked(fetch).mockResolvedValue(new Response("{}", { status: 200 }))

        const config = MicrosoftEntraID({
          clientId: "test-client-id",
          clientAssertion: clientAssertionFn,
        })

        const fetchHandler = config[customFetch]!
        await fetchHandler(
          "https://login.microsoftonline.com/test-tenant/oauth2/v2.0/token",
          { method: "POST", body: JSON.stringify({ code: "auth-code" }) }
        )

        expect(clientAssertionFn).not.toHaveBeenCalled()
      })

      it("should throw descriptive error when clientAssertion callback fails", async () => {
        const config = MicrosoftEntraID({
          clientId: "test-client-id",
          issuer: "https://login.microsoftonline.com/test-tenant/v2.0",
          clientAssertion: async () => {
            throw new Error("ENOENT: no such file or directory")
          },
        })

        const fetchHandler = config[customFetch]!
        const body = new URLSearchParams({ grant_type: "authorization_code" })

        await expect(
          fetchHandler(
            "https://login.microsoftonline.com/test-tenant/oauth2/v2.0/token",
            { method: "POST", body }
          )
        ).rejects.toThrow(
          "Failed to get client assertion: ENOENT: no such file or directory"
        )
      })
    })

    describe("customFetch OIDC discovery", () => {
      beforeEach(() => {
        vi.stubGlobal("fetch", vi.fn())
      })

      afterEach(() => {
        vi.unstubAllGlobals()
      })

      it("should fix {tenantid} placeholder in discovery response", async () => {
        const discoveryResponse = {
          issuer: "https://login.microsoftonline.com/{tenantid}/v2.0",
          token_endpoint:
            "https://login.microsoftonline.com/mytenant/oauth2/v2.0/token",
        }

        vi.mocked(fetch).mockResolvedValue(
          new Response(JSON.stringify(discoveryResponse), { status: 200 })
        )

        const config = MicrosoftEntraID({
          clientId: "test-client-id",
          clientSecret: "test-secret",
          issuer: "https://login.microsoftonline.com/mytenant/v2.0",
        })

        const fetchHandler = config[customFetch]!
        const response = await fetchHandler(
          "https://login.microsoftonline.com/mytenant/v2.0/.well-known/openid-configuration"
        )

        const json = await response.json()
        expect(json.issuer).toBe(
          "https://login.microsoftonline.com/mytenant/v2.0"
        )
      })

      it("should use 'common' for {tenantid} when issuer format is unexpected", async () => {
        const discoveryResponse = {
          issuer: "https://login.microsoftonline.com/{tenantid}/v2.0",
        }

        vi.mocked(fetch).mockResolvedValue(
          new Response(JSON.stringify(discoveryResponse), { status: 200 })
        )

        const config = MicrosoftEntraID({
          clientId: "test-client-id",
          clientSecret: "test-secret",
          issuer: "https://some-other-issuer.com/v2.0",
        })

        const fetchHandler = config[customFetch]!
        const response = await fetchHandler(
          "https://some-other-issuer.com/v2.0/.well-known/openid-configuration"
        )

        const json = await response.json()
        expect(json.issuer).toBe(
          "https://login.microsoftonline.com/common/v2.0"
        )
      })
    })
  })
})
