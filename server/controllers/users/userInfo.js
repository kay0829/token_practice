const { USER_DATA } = require("../../db/data");
// JWT는 verifyToken으로 검증할 수 있습니다. 먼저 tokenFunctions에 작성된 여러 메서드들의 역할을 파악하세요.
const { verifyToken, generateToken } = require("../helper/tokenFunctions");

module.exports = async (req, res) => {
  /*
   * TODO: 토큰 검증 여부에 따라 유저 정보를 전달하는 로직을 구현하세요.
   *
   * Access Token에 대한 검증이 성공하면 복호화된 payload를 이용하여 USER_DATA에서 해당하는 유저를 조회할 수 있습니다.
   * Access Token이 만료되었다면 Refresh Token을 검증해 Access Token을 재발급하여야 합니다.
   * Access Token과 Refresh Token 모두 만료되었다면 상태 코드 401을 보내야합니다.
   */
  const cookiesOption = {
    domain: "localhost",
    path: "/",
    httpOnly: true,
    sameSite: "strict",
    secure: true,
  };
  res.cookie("checkedKeepLogin", true, cookiesOption);
  console.log("req.cookies", req.cookies);

  const accessToken = req.cookies.access_jwt;
  const refreshToken = req.cookies.refresh_jwt;
  let AT = verifyToken("access", accessToken);
  let RT = null;

  // accessToken이 없으면 401 에러
  if (!accessToken) {
    res.status(401).send("Not Authorized");
    return;
  }

  // accessToken이 유효하지 않으면 401 에러
  if (AT.jwt === "invalid") {
    res.status(401).send("Not Authorized");
    return;
  }

  if (AT.jwt === "expired" && refreshToken) {
    // accessToken이 만료되었는데 refreshToken이 없으면 401 에러
    if (!refreshToken) {
      res.status(401).send("Not Authorized");
      return;
    }

    // refreshToken 유효성 검사
    RT = verifyToken("refresh", refreshToken);

    // accessToken이 만료되었는데 refreshToken도 만료되었거나 유효하지 않을 경우 401 에러
    if (RT.jwt === "invalid" || RT.jwt === "expired") {
      res.status(401).send("Not Authorized");
      return;
    }

    // refreshToken에서 얻은 데이터 중 id로 해당하는 유저 찾기
    const userInfo = {
      ...USER_DATA.filter((user) => user.id === RT.id)[0],
    };

    // 유효한 refreshToken 으로 accessToken 다시 요청하기
    const checkedKeepLogin = req.cookies.checkedKeepLogin;
    const token = generateToken(userInfo, checkedKeepLogin);

    // accessToekn 유효성 다시 검사 및 새로운 accessToken 저장
    AT = verifyToken("access", token);
    res.cookie("access_jwt", token, cookiesOption);
  }

  // accessToken에서 얻은 데이터 중 id로 해당하는 유저 찾기
  const userInfo = {
    ...USER_DATA.filter((user) => user.id === AT.id)[0],
  };

  // password를 제외한 유저 정보 보내기
  delete userInfo.password;
  res.send(userInfo);
};
