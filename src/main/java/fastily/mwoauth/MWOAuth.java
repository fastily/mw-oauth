package fastily.mwoauth;

import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.builder.api.DefaultApi10a;
import com.github.scribejava.core.model.OAuth1AccessToken;
import com.github.scribejava.core.model.OAuth1RequestToken;
import com.github.scribejava.core.oauth.OAuth10aService;
import com.github.scribejava.httpclient.okhttp.OkHttpHttpClientConfig;

/**
 * A simple interface that allows an app to authenticate via MediaWiki's OAuth 1.0a process.
 * 
 * @author Fastily
 *
 */
public class MWOAuth
{
	/**
	 * Represents the MediaWiki OAuth 1.0a service to interact with.
	 */
	public final OAuth10aService service;

	/**
	 * The request token obtained from the first step of the OAuth 1.0a process.
	 */
	private OAuth1RequestToken requestToken;

	/**
	 * Constructor, creates a new MWOAuth object.
	 * 
	 * @param consumerID The consumer token/id/key identifying this OAuth consumer. MediaWiki also refers to this as a
	 *           "consumer key".
	 * @param clientSecret The secret token obtained from <a
	 *           href=https://meta.wikimedia.org/wiki/Special:OAuthConsumerRegistration/propose>proposing</a> a new
	 *           consumer.
	 * @param hostname The hostname of the Wiki to interface with. Example: for the <a
	 *           href=https://en.wikipedia.org/wiki/Main_Page>English Wikipedia</a>, use {@code en.wikipedia.org}.
	 */
	public MWOAuth(String consumerID, String clientSecret, String hostname)
	{
		service = new ServiceBuilder(consumerID).apiSecret(clientSecret).httpClientConfig(OkHttpHttpClientConfig.defaultConfig())
				.build(new API(hostname, consumerID));
	}

	/**
	 * Performs the first 1.5 steps in OAuth 1.0a. Specifically: get a request token and returns the authorization url
	 * the user should be directed to.
	 * 
	 * @return The authorization URL to direct the user to.
	 * @throws Throwable Network error
	 */
	public String getAuthorizationURL() throws Throwable
	{
		requestToken = service.getRequestToken();
		System.out.println("Request Token was: " + requestToken.getToken());
		System.out.println("Raw response is: " + requestToken.getRawResponse());

		return service.getAuthorizationUrl(requestToken);
	}

	/**
	 * Performs the last 1.5 steps in OAuth 1.0a. Specifically: use the {@code oauth_verifier} returned by the server to
	 * get an access token from the server.
	 * 
	 * @param oauthVerifier The {@code oauth_verifier} parameter value returned in the URL from the server (assuming
	 *           successful authentication)
	 * @return The OAuth access token, or null on error/user deny.
	 * @throws Throwable Network error
	 */
	public OAuth1AccessToken getAccessToken(String oauthVerifier) throws Throwable
	{
		OAuth1AccessToken accessToken = service.getAccessToken(requestToken, oauthVerifier);
		System.out.println(accessToken.getRawResponse());

		return accessToken;
	}

	/**
	 * Generates endpoints for MediaWiki's OAuth 1.0a process.
	 * 
	 * @author Fastily
	 *
	 */
	private class API extends DefaultApi10a
	{
		/**
		 * The consumer token/id identifying this OAuth consumer.
		 */
		private String consumerID;

		/**
		 * The ugly base URL. Required because <a href=https://phabricator.wikimedia.org/T74186>T74186</a>.
		 */
		private String uglyBaseURL;

		/**
		 * This is a pretty base URL. Required because <a href=https://phabricator.wikimedia.org/T74186>T74186</a>.
		 */
		private String prettyBaseURL;

		/**
		 * Constructor, creates a new API object.
		 * 
		 * @param hostname The hostname of the Wiki to interface with.
		 * @param consumerID The consumer token/id identifying this OAuth consumer.
		 */
		private API(String hostname, String consumerID)
		{
			this.consumerID = consumerID;

			uglyBaseURL = String.format("https://%s/w/index.php?title=Special:OAuth/", hostname);
			prettyBaseURL = String.format("https://%s/wiki/Special:OAuth/", hostname);
		}

		/**
		 * Produces the request token endpoint. This is used for step 1 of the OAuth 1.0a process.
		 */
		@Override
		public String getRequestTokenEndpoint()
		{
			return uglyBaseURL + "initiate";
		}

		/**
		 * Produces the authorization URL endpoint. This is used for step 2 of the OAuth 1.0a process.
		 * 
		 */
		@Override
		public String getAuthorizationUrl(OAuth1RequestToken requestToken)
		{
			return String.format("%sauthorize?oauth_consumer_key=%s&oauth_token=%s", prettyBaseURL, consumerID, requestToken.getToken());
		}

		/**
		 * Produces the access token endpoint. This is used for step 3 of the OAuth 1.0a process.
		 */
		@Override
		public String getAccessTokenEndpoint()
		{
			return uglyBaseURL + "token";
		}

		/**
		 * Disabled/Throws UnsupportedOperationException. MediaWiki uses 2 different base URLs.
		 */
		@Override
		protected String getAuthorizationBaseUrl()
		{
			throw new UnsupportedOperationException("");
		}
	}
}